/* eslint-disable valid-jsdoc */
import { EntityManager } from "typeorm"
import { MedusaError } from "medusa-core-utils"
import { FileService } from "medusa-interfaces"
import * as IORedis from "ioredis"

import { ProductVariantRepository } from "../../repositories/product-variant"
import { ProductOptionRepository } from "../../repositories/product-option"
import { AbstractBatchJobStrategy, IFileService } from "../../interfaces"
import { ProductRepository } from "../../repositories/product"
import { RegionRepository } from "../../repositories/region"
import { CsvSchema } from "../../interfaces/csv-parser"
import CsvParser from "../../services/csv-parser"
import { ProductOption } from "../../models"
import {
  BatchJobService,
  ProductService,
  ProductVariantService,
  ShippingProfileService,
} from "../../services"
import { CreateProductInput } from "../../types/product"
import {
  CreateProductVariantInput,
  UpdateProductVariantInput,
} from "../../types/product-variant"

/* ******************** TYPES ******************** */

type ProductImportCsvSchema = CsvSchema<
  Record<string, string>,
  Record<string, string>
>

type TParsedRowData = Record<
  string,
  string | number | (string | number | object)[]
>

type ImportJobContext = {
  total: number
  progress: number
  fileKey: string
}

/**
 * Supported batch job ops.
 */
enum OperationType {
  ProductCreate = "PRODUCT_CREATE",
  ProductUpdate = "PRODUCT_UPDATE",
  VariantCreate = "VARIANT_CREATE",
  VariantUpdate = "VARIANT_UPDATE",
}

/**
 * Process this many variant rows before reporting progress.
 */
const BATCH_SIZE = 100

/* ******************** UTILS ******************** */

/**
 * Pick keys for a new object by regex.
 * @param data - Initial data object
 * @param regex - A regex used to pick which keys are going to be copied in the new object
 */
function pickObjectPropsByRegex(
  data: TParsedRowData,
  regex: RegExp
): TParsedRowData {
  const variantKeyPredicate = (key: string): boolean => regex.test(key)
  const ret = {}

  for (const k in data) {
    if (variantKeyPredicate(k)) {
      ret[k] = data[k]
    }
  }

  return ret
}

/**
 * Pick data from parsed CSV object relevant for product create/update and remove prefixes from keys.
 */
function transformProductData(data: TParsedRowData): TParsedRowData {
  const ret = {}
  const productData = pickObjectPropsByRegex(data, /product\./)

  Object.keys(productData).forEach((k) => {
    const key = k.split("product.")[1]
    ret[key] = productData[k]
  })

  return ret
}

/**
 * Pick data from parsed CSV object relevant for variant create/update and remove prefixes from keys.
 */
function transformVariantData(data: TParsedRowData): TParsedRowData {
  const ret = {}
  const productData = pickObjectPropsByRegex(data, /variant\./)

  Object.keys(productData).forEach((k) => {
    const key = k.split("variant.")[1]
    ret[key] = productData[k]
  })

  // include product handle to keep track of associated product
  ret["product.handle"] = data["product.handle"]
  ret["product.options"] = data["product.options"]

  return ret
}

/**
 * Default strategy class used for a batch import of products/variants.
 */
class ProductImportStrategy extends AbstractBatchJobStrategy<ProductImportStrategy> {
  static identifier = "product-import"

  static batchType = "product_import"

  private processedCounter = 0

  protected readonly redisClient_: IORedis.Redis

  protected manager_: EntityManager
  protected transactionManager_: EntityManager | undefined

  protected readonly fileService_: IFileService<typeof FileService>

  protected readonly productService_: ProductService
  protected readonly batchJobService_: BatchJobService
  protected readonly productVariantService_: ProductVariantService
  protected readonly shippingProfileService_: typeof ShippingProfileService

  protected readonly regionRepo_: typeof RegionRepository
  protected readonly productRepo_: typeof ProductRepository
  protected readonly productOptionRepo_: typeof ProductOptionRepository
  protected readonly productVariantRepo_: typeof ProductVariantRepository

  protected readonly csvParser_: CsvParser<
    ProductImportCsvSchema,
    Record<string, string>,
    Record<string, string>
  >

  constructor(container) {
    super(container)

    const {
      batchJobService,
      productService,
      productRepository,
      productOptionRepository,
      productVariantService,
      productVariantRepository,
      shippingProfileService,
      regionRepository,
      fileService,
      redisClient,
      manager,
    } = container

    this.csvParser_ = new CsvParser(container, CSVSchema)

    this.manager_ = manager
    this.redisClient_ = redisClient
    this.fileService_ = fileService
    this.batchJobService_ = batchJobService
    this.productService_ = productService
    this.productVariantService_ = productVariantService
    this.shippingProfileService_ = shippingProfileService
    this.productRepo_ = productRepository
    this.productOptionRepo_ = productOptionRepository
    this.productVariantRepo_ = productVariantRepository
    this.regionRepo_ = regionRepository
  }

  buildTemplate(): Promise<string> {
    throw new Error("Not implemented!")
  }

  /**
   * Generate instructions for update/create of products/variants from parsed CSV rows.
   *
   * @param csvData - An array of parsed CSV rows.
   */
  async getImportInstructions(
    csvData: TParsedRowData[]
  ): Promise<Record<OperationType, TParsedRowData[]>> {
    const regionRepo = this.manager_.getCustomRepository(this.regionRepo_)

    const shippingProfile = await this.shippingProfileService_.retrieveDefault()

    const seenProducts = {}

    const productsCreate: TParsedRowData[] = []
    const productsUpdate: TParsedRowData[] = []

    const variantsCreate: TParsedRowData[] = []
    const variantsUpdate: TParsedRowData[] = []

    for (const row of csvData) {
      if ((row["variant.prices"] as object[]).length) {
        await this.handleVariantPrices(row, regionRepo)
      }

      if (row["variant.id"]) {
        variantsUpdate.push(row)
      } else {
        variantsCreate.push(row)
      }

      // save only first occurrence
      if (!seenProducts[row["product.handle"] as string]) {
        row["product.profile_id"] = shippingProfile
        ;(row["product.product.id"] ? productsUpdate : productsCreate).push(row)

        seenProducts[row["product.handle"] as string] = true
      }
    }

    return {
      [OperationType.ProductCreate]: productsCreate,
      [OperationType.VariantCreate]: variantsCreate,
      [OperationType.ProductUpdate]: productsUpdate,
      [OperationType.VariantUpdate]: variantsUpdate,
    }
  }

  /**
   * Prepare prices records for insert - find and append region ids to records that contain a region name.
   *
   * @param row - An object containing parsed row data.
   * @param regionRepo - Region repository.
   */
  protected async handleVariantPrices(
    row,
    regionRepo: RegionRepository
  ): Promise<void> {
    const prices: Record<string, string | number>[] = []

    for (const p of row["variant.prices"]) {
      const record: Record<string, string | number> = {
        amount: p.amount,
      }

      if (p.regionName) {
        const region = await regionRepo.findOne({
          where: { name: p.regionName },
        })

        if (!region) {
          throw new MedusaError(
            MedusaError.Types.INVALID_DATA,
            `Trying to set a price for a region ${p.regionName} that doesn't exist`
          )
        }

        record.region_id = region!.id
      } else {
        record.currency_code = p.currency_code
      }

      prices.push(record)
    }

    row["variant.prices"] = prices
  }

  /**
   * A worker method called after a batch job has been created.
   * The method parses a CSV file, generates sets of instructions
   * for processing and stores these instructions to Redis.
   *
   * @param batchJobId . An id of a job that is being preprocessed.
   */
  async preProcessBatchJob(batchJobId: string): Promise<void> {
    const batchJob = await this.batchJobService_.retrieve(batchJobId)

    const csvFileKey = (batchJob.context as ImportJobContext).fileKey
    const csvStream = await this.fileService_.getDownloadStream({
      fileKey: csvFileKey,
    })

    const data = await this.csvParser_.parse(csvStream)
    const results = await this.csvParser_.buildData(data)

    const ops = await this.getImportInstructions(results)

    await this.setImportDataToRedis(batchJobId, ops)

    await this.batchJobService_.update(batchJobId, {
      context: {
        // number of update/create operations to execute
        total: Object.keys(ops).reduce((acc, k) => acc + ops[k].length, 0),
      },
    })
  }

  /**
   * The main processing method called after a batch job
   * is ready/confirmed for processing.
   *
   * @param batchJobId - An id of a batch job that is being processed.
   */
  async processJob(batchJobId: string): Promise<void> {
    return await this.atomicPhase_(async (transactionManager) => {
      await this.createProducts(batchJobId, transactionManager)
      await this.updateProducts(batchJobId, transactionManager)
      await this.createVariants(batchJobId, transactionManager)
      await this.updateVariants(batchJobId, transactionManager)

      this.finalize_(batchJobId)
    })
  }

  /**
   * Method creates products using `ProductService` and parsed data from a CSV row.
   *
   * @param batchJobId - An id of the current batch job being processed.
   * @param transactionManager - Transaction manager responsible for current batch import.
   */
  private async createProducts(
    batchJobId: string,
    transactionManager: EntityManager
  ): Promise<void> {
    const productOps = await this.getImportDataFromRedis(
      batchJobId,
      OperationType.ProductCreate
    )

    for (const productOp of productOps) {
      try {
        await this.productService_
          .withTransaction(transactionManager)
          .create(
            transformProductData(productOp) as unknown as CreateProductInput
          )
      } catch (e) {
        this.handleImportError_(productOp)
      }

      this.updateProgress_(batchJobId)
    }
  }

  /**
   * Method updates existing products in the DB using a CSV row data.
   *
   * @param batchJobId - An id of the current batch job being processed.
   * @param transactionManager - Transaction manager responsible for current batch import.
   */
  private async updateProducts(
    batchJobId: string,
    transactionManager: EntityManager
  ): Promise<void> {
    const productOps = await this.getImportDataFromRedis(
      batchJobId,
      OperationType.ProductUpdate
    )

    for (const productOp of productOps) {
      try {
        await this.productService_
          .withTransaction(transactionManager)
          .update(
            productOp["product.id"] as string,
            transformProductData(productOp)
          )
      } catch (e) {
        this.handleImportError_(productOp)
      }

      this.updateProgress_(batchJobId)
    }
  }

  /**
   * Method creates product variants from a CSV data.
   * Method also handles processing of variant options.
   *
   * @param batchJobId - An id of the current batch job being processed.
   * @param transactionManager - Transaction manager responsible for current batch import.
   */
  private async createVariants(
    batchJobId: string,
    transactionManager: EntityManager
  ): Promise<void> {
    const productRepo = transactionManager.getCustomRepository(
      this.productRepo_
    )

    const variantOps = await this.getImportDataFromRedis(
      batchJobId,
      OperationType.VariantCreate
    )

    for (const variantOp of variantOps) {
      try {
        const variant = transformVariantData(variantOp)

        const product = await productRepo.findOne({
          where: { handle: variantOp["product.handle"] },
          relations: ["variants", "variants.options", "options"],
        })

        const optionIds =
          (variantOp["product.options"] as Record<string, string>[])?.map(
            (variantOption) =>
              product!.options.find(
                (createdProductOption) =>
                  createdProductOption.title === variantOption.title
              )!.id
          ) || []

        variant.options =
          (variant.options as object[])?.map((o, index) => ({
            ...o,
            option_id: optionIds[index],
          })) || []

        await this.productVariantService_
          .withTransaction(transactionManager)
          .create(product!, variant as unknown as CreateProductVariantInput)

        this.updateProgress_(batchJobId)
      } catch (e) {
        this.handleImportError_(variantOp)
      }
    }
  }

  /**
   * Method updates product variants from a CSV data.
   *
   * @param batchJobId - An id of the current batch job being processed.
   * @param transactionManager - Transaction manager responsible for current batch import.
   */
  private async updateVariants(
    batchJobId: string,
    transactionManager: EntityManager
  ): Promise<void> {
    const productOptionRepo = this.manager_.getCustomRepository(
      this.productOptionRepo_
    )

    const variantOps = await this.getImportDataFromRedis(
      batchJobId,
      OperationType.VariantUpdate
    )

    for (const variantOp of variantOps) {
      try {
        await this.prepareVariantOptions(variantOp, productOptionRepo)

        await this.productVariantService_
          .withTransaction(transactionManager)
          .update(
            variantOp["variant.id"] as string,
            transformVariantData(variantOp) as UpdateProductVariantInput
          )
      } catch (e) {
        this.handleImportError_(variantOp)
      }

      this.updateProgress_(batchJobId)
    }
  }

  /**
   * Extend records used for creating variant options with corresponding product option ids.
   *
   * @param variantOp Parsed row data form CSV
   * @param productOptionRepo ProductOption repository
   */
  protected async prepareVariantOptions(
    variantOp,
    productOptionRepo: ProductOptionRepository
  ): Promise<void> {
    const productOptions = variantOp["variant.options"] || []

    for (const o of productOptions) {
      const { id } = (await productOptionRepo.findOne({
        where: { title: o._title },
      })) as ProductOption

      o.option_id = id
    }
  }

  /**
   * Store import ops JSON to Redis.
   * Data will expire after an hour.
   *
   * @param batchJobId - An id of the current batch job being processed.
   * @param results - An object containing parsed CSV data.
   */
  async setImportDataToRedis(
    batchJobId: string,
    results: Record<OperationType, TParsedRowData[]>
  ): Promise<void> {
    for (const op in results) {
      if (results[op]?.length) {
        await this.redisClient_.set(
          `pij_${batchJobId}:${op}`,
          JSON.stringify(results[op]),
          "EX",
          60 * 60
        )
      }
    }
  }

  /**
   * Retrieve parsed CSV data from Redis.
   *
   * @param batchJobId - An id of the current batch job being processed.
   * @param op - Type of import operation.
   */
  async getImportDataFromRedis(
    batchJobId: string,
    op: OperationType
  ): Promise<TParsedRowData[]> {
    return JSON.parse(
      (await this.redisClient_.get(`pij_${batchJobId}:${op}`)) || "[]"
    )
  }

  async clearRedisRecords(batchJobId: string): Promise<number> {
    return await this.redisClient_.del(`pij_${batchJobId}:*`)
  }

  /**
   * Update count of processed data in the batch job context.
   *
   * @param batchJobId - An id of the current batch job being processed.
   */
  private async finalize_(batchJobId: string): Promise<void> {
    const batchJob = await this.batchJobService_.retrieve(batchJobId)

    await this.batchJobService_.update(batchJobId, {
      context: { progress: batchJob.context.total },
    })
  }

  /**
   * Store the progress in the batch job context.
   * Method is called after every update/create operation,
   * but after every `BATCH_SIZE`processed rows info is written to the DB.
   *
   * @param batchJobId - An id of the current batch job being processed.
   */
  private async updateProgress_(batchJobId: string): Promise<void> {
    this.processedCounter += 1

    if (this.processedCounter % BATCH_SIZE !== 0) {
      return
    }

    await this.batchJobService_.update(batchJobId, {
      context: { progress: this.processedCounter },
    })
  }

  /**
   * Create a description of a row on which an error occurred and throw a Medusa error.
   *
   * @param row - Parsed CSV row data-
   */
  private handleImportError_(row: TParsedRowData): unknown {
    const message = `Error while processing row with:
      product id: ${row["product.id"]},
      product handle: ${row["product.handle"]},
      variant id: ${row["variant.id"]}
      variant sku: ${row["variant.sku"]}`

    throw new MedusaError(MedusaError.Types.INVALID_DATA, message)
  }
}

export default ProductImportStrategy

/**
 * Schema definition for the CSV parser.
 */
const CSVSchema: ProductImportCsvSchema = {
  columns: [
    // PRODUCT
    {
      name: "Product id",
      mapTo: "product.id",
    },
    {
      name: "Product Handle",
      mapTo: "product.handle",
      required: true,
    },
    { name: "Product Title", mapTo: "product.title" },
    { name: "Product Subtitle", mapTo: "product.subtitle" },
    { name: "Product Description", mapTo: "product.description" },
    { name: "Product Status", mapTo: "product.status" },
    { name: "Product Thumbnail", mapTo: "product.thumbnail" },
    { name: "Product Weight", mapTo: "product.weight" },
    { name: "Product Length", mapTo: "product.length" },
    { name: "Product Width", mapTo: "product.width" },
    { name: "Product Height", mapTo: "product.height" },
    { name: "Product HS Code", mapTo: "product.hs_code" },
    { name: "Product Origin Country", mapTo: "product.origin_country" },
    { name: "Product Mid Code", mapTo: "product.mid_code" },
    { name: "Product Material", mapTo: "product.material" },
    // PRODUCT-COLLECTION
    { name: "Product Collection Title", mapTo: "product.collection.title" },
    { name: "Product Collection Handle", mapTo: "product.collection.handle" },
    // PRODUCT-TYPE
    { name: "Product Type", mapTo: "product.type.value" },
    // PRODUCT-TAGS
    {
      name: "Product Tags",
      mapTo: "product.tags",
      transform: (value: string) =>
        `${value}`.split(",").map((v) => ({ value: v })),
    },
    //
    { name: "Product Discountable", mapTo: "product.discountable" },
    { name: "Product External ID", mapTo: "product.external_id" },
    // PRODUCT-SHIPPING_PROFILE
    { name: "Product Profile Name", mapTo: "product.profile.name" },
    { name: "Product Profile Type", mapTo: "product.profile.type" },
    // Variants
    {
      name: "Variant id",
      mapTo: "variant.id",
    },
    { name: "Variant Title", mapTo: "variant.title" },
    { name: "Variant SKU", mapTo: "variant.sku" },
    { name: "Variant Barcode", mapTo: "variant.barcode" },
    { name: "Variant Inventory Quantity", mapTo: "variant.inventory_quantity" },
    { name: "Variant Allow backorder", mapTo: "variant.allow_backorder" },
    { name: "Variant Manage inventory", mapTo: "variant.manage_inventory" },
    { name: "Variant Weight", mapTo: "variant.weight" },
    { name: "Variant Length", mapTo: "variant.length" },
    { name: "Variant Width", mapTo: "variant.width" },
    { name: "Variant Height", mapTo: "variant.height" },
    { name: "Variant HS Code", mapTo: "variant.hs_code" },
    { name: "Variant Origin Country", mapTo: "variant.origin_country" },
    { name: "Variant Mid Code", mapTo: "variant.mid_code" },
    { name: "Variant Material", mapTo: "variant.material" },

    // ==== DYNAMIC FIELDS ====

    // PRODUCT_OPTIONS
    {
      name: "Option Name",
      match: /Option \d+ Name/,
      // @ts-ignore
      reducer: (builtLine: TParsedRowData, key: string, value: string) => {
        builtLine["product.options"] = builtLine["product.options"] || []

        if (typeof value === "undefined" || value === null) {
          return builtLine
        }
        ;(
          builtLine["product.options"] as Record<string, string | number>[]
        ).push({ title: value })

        return builtLine
      },
    },
    {
      name: "Option Value",
      match: /Option \d+ Value/,
      // @ts-ignore
      reducer: (
        builtLine: TParsedRowData,
        key: string,
        value: string,
        context: any
      ) => {
        builtLine["variant.options"] = builtLine["variant.options"] || []

        if (typeof value === "undefined" || value === null) {
          return builtLine
        }

        ;(
          builtLine["variant.options"] as Record<string, string | number>[]
        ).push({
          value,
          _title: context.line[key.slice(0, -6) + " Name"],
        })

        return builtLine
      },
    },
    // Prices
    {
      name: "Price Region",
      match: /Price .* \[([A-Z]{2,4})\]/,
      // @ts-ignore
      reducer: (builtLine: TParsedRowData, key, value) => {
        builtLine["variant.prices"] = builtLine["variant.prices"] || []

        if (typeof value === "undefined" || value === null) {
          return builtLine
        }

        const regionName = key.split(" ")[1]

        ;(
          builtLine["variant.prices"] as Record<string, string | number>[]
        ).push({
          amount: value,
          regionName,
        })

        return builtLine
      },
    },
    {
      name: "Price Currency",
      match: /Price [A-Z]{2,4}/,
      // @ts-ignore
      reducer: (builtLine: TParsedRowData, key, value) => {
        builtLine["variant.prices"] = builtLine["variant.prices"] || []

        if (typeof value === "undefined" || value === null) {
          return builtLine
        }

        const currency = key.split(" ")[1]

        ;(
          builtLine["variant.prices"] as Record<string, string | number>[]
        ).push({
          amount: value,
          currency_code: currency,
        })

        return builtLine
      },
    },
    // Images
    {
      name: "Image Url",
      match: /Image \d+ Url/,
      // @ts-ignore
      reducer: (builtLine: any, key, value) => {
        builtLine["product.images"] = builtLine["product.images"] || []

        if (typeof value === "undefined" || value === null) {
          return builtLine
        }

        builtLine["product.images"].push(value)

        return builtLine
      },
    },
  ],
}
