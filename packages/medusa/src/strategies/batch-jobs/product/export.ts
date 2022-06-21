import { EntityManager } from "typeorm"
import { AbstractBatchJobStrategy, IFileService } from "../../../interfaces"
import { Product, ProductVariant } from "../../../models"
import { BatchJobService, ProductService } from "../../../services"
import { BatchJobStatus, CreateBatchJobInput } from "../../../types/batch-job"
import { defaultAdminProductRelations } from "../../../api/routes/admin/products"
import { prepareListQuery } from "../../../utils/get-query-config"
import {
  ProductExportBatchJob,
  ProductExportBatchJobContext,
  ProductExportColumnSchemaDescriptor,
  ProductExportPriceData,
  productExportSchemaDescriptors,
} from "./index"
import { FindProductConfig } from "../../../types/product"

type InjectedDependencies = {
  manager: EntityManager
  batchJobService: BatchJobService
  productService: ProductService
  fileService: IFileService<never>
}

export default class ProductExportStrategy extends AbstractBatchJobStrategy<
  ProductExportStrategy,
  InjectedDependencies
> {
  public static identifier = "product-export-strategy"
  public static batchType = "product-export"

  protected manager_: EntityManager
  protected transactionManager_: EntityManager | undefined

  protected readonly batchJobService_: BatchJobService
  protected readonly productService_: ProductService
  protected readonly fileService_: IFileService<never>

  protected readonly defaultRelations_ = [
    ...defaultAdminProductRelations,
    "variants.prices.region",
  ]
  /*
   *
   * The dynamic columns corresponding to the lowest level of relations are built later on.
   * You can have a look at the buildHeader method that take care of appending the other
   * column descriptors to this map.
   *
   */
  protected readonly columnDescriptors: Map<
    string,
    ProductExportColumnSchemaDescriptor
  > = productExportSchemaDescriptors

  private readonly NEWLINE_ = "\r\n"
  private readonly DELIMITER_ = ";"
  private readonly BATCH_SIZE = 50

  constructor({
    manager,
    batchJobService,
    productService,
    fileService,
  }: InjectedDependencies) {
    super({
      manager,
      batchJobService,
      productService,
      fileService,
    })

    this.manager_ = manager
    this.batchJobService_ = batchJobService
    this.productService_ = productService
    this.fileService_ = fileService
  }

  async buildTemplate(): Promise<string> {
    return ""
  }

  async preProcessBatchJob(batchJobId: string): Promise<void> {
    return await this.atomicPhase_(async (transactionManager) => {
      const batchJob = (await this.batchJobService_
        .withTransaction(transactionManager)
        .retrieve(batchJobId)) as ProductExportBatchJob

      let offset = batchJob.context?.list_config?.skip ?? 0
      const limit = this.BATCH_SIZE

      const { list_config = {}, filterable_fields = {} } = batchJob.context
      const [productList, count] = await this.productService_
        .withTransaction(transactionManager)
        .listAndCount(filterable_fields, list_config as FindProductConfig)

      const productCount = count
      let products: Product[] = productList

      let dynamicOptionColumnCount = 0
      let dynamicImageColumnCount = 0

      const pricesData = new Set<string>()

      while (offset < productCount) {
        if (!products?.length) {
          products = await this.productService_
            .withTransaction(transactionManager)
            .list(filterable_fields, {
              ...list_config,
              skip: offset,
              take: limit,
            } as FindProductConfig)
        }

        // Retrieve the highest count of each object to build the dynamic columns later
        for (const product of products) {
          const optionsCount = product?.options?.length ?? 0
          dynamicOptionColumnCount = Math.max(
            dynamicOptionColumnCount,
            optionsCount
          )

          const imageCount = product?.images?.length ?? 0
          dynamicImageColumnCount = Math.max(
            dynamicImageColumnCount,
            imageCount
          )

          for (const variant of product.variants) {
            if (variant.prices?.length) {
              variant.prices.forEach((price) => {
                pricesData.add(
                  JSON.stringify({
                    currency_code:
                      price.currency_code ?? price?.region?.currency_code,
                    region: price.region
                      ? { name: price.region.name, id: price.region.id }
                      : undefined,
                  })
                )
              })
            }
          }
        }

        offset += products.length
        products = []
      }

      await this.batchJobService_
        .withTransaction(transactionManager)
        .update(batchJob, {
          context: {
            shape: {
              dynamicImageColumnCount,
              dynamicOptionColumnCount,
              prices: [...pricesData].map((stringifyData) =>
                JSON.parse(stringifyData)
              ),
            },
          },
        })
    })
  }

  async prepareBatchJobForProcessing(
    batchJob: CreateBatchJobInput,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    req: Express.Request
  ): Promise<CreateBatchJobInput> {
    const {
      limit,
      offset,
      order,
      fields,
      expand,
      filterable_fields,
      ...context
    } = (batchJob?.context ?? {}) as ProductExportBatchJobContext

    const listConfig = prepareListQuery(
      {
        limit,
        offset,
        order,
        fields,
        expand,
      },
      {
        isList: true,
        defaultRelations: this.defaultRelations_,
      }
    )

    batchJob.context = {
      ...(context ?? {}),
      list_config: listConfig,
      filterable_fields,
    }

    return batchJob
  }

  async processJob(batchJobId: string): Promise<void> {
    let offset = 0
    let limit = this.BATCH_SIZE
    let advancementCount = 0
    let productCount = 0

    return await this.atomicPhase_(
      async (transactionManager) => {
        let batchJob = (await this.batchJobService_
          .withTransaction(transactionManager)
          .retrieve(batchJobId)) as ProductExportBatchJob

        const { writeStream, fileKey, promise } = await this.fileService_
          .withTransaction(transactionManager)
          .getUploadStreamDescriptor({
            name: "product-export",
            ext: "csv",
          })

        const header = await this.buildHeader(batchJob)
        writeStream.write(header)

        advancementCount =
          batchJob.result?.advancement_count ?? advancementCount
        offset = (batchJob.context?.list_config?.skip ?? 0) + advancementCount
        limit = batchJob.context?.list_config?.take ?? this.BATCH_SIZE

        const { list_config = {}, filterable_fields = {} } = batchJob.context
        const [productList, count] = await this.productService_
          .withTransaction(transactionManager)
          .listAndCount(filterable_fields, {
            ...list_config,
            skip: offset,
            take: limit,
          } as FindProductConfig)

        productCount = count
        let products: Product[] = productList

        while (offset < productCount) {
          if (!products?.length) {
            products = await this.productService_
              .withTransaction(transactionManager)
              .list(filterable_fields, {
                ...list_config,
                skip: offset,
                take: limit,
              } as FindProductConfig)
          }

          products.forEach((product: Product) => {
            const lines = this.buildProductVariantLines(product)
            lines.forEach((line) => writeStream.write(line))
          })

          advancementCount += products.length
          offset += products.length
          products = []

          batchJob = (await this.batchJobService_
            .withTransaction(transactionManager)
            .update(batchJobId, {
              result: {
                file_key: fileKey,
                count: productCount,
                advancement_count: advancementCount,
                progress: advancementCount / productCount,
              },
            })) as ProductExportBatchJob

          if (batchJob.status === BatchJobStatus.CANCELED) {
            writeStream.end()

            await this.fileService_
              .withTransaction(transactionManager)
              .delete({ key: fileKey })
            return
          }
        }

        writeStream.end()

        return await promise
      },
      "REPEATABLE READ",
      async (err) =>
        this.handleProcessingError(batchJobId, err, {
          count: productCount,
          advancement_count: advancementCount,
          progress: advancementCount / productCount,
        })
    )
  }

  public async buildHeader(batchJob: ProductExportBatchJob): Promise<string> {
    const {
      prices = [],
      dynamicImageColumnCount,
      dynamicOptionColumnCount,
    } = batchJob?.context?.shape ?? {}

    this.appendMoneyAmountDescriptors(prices)
    this.appendOptionsDescriptors(dynamicOptionColumnCount)
    this.appendImagesDescriptors(dynamicImageColumnCount)

    return (
      [...this.columnDescriptors.keys()].join(this.DELIMITER_) + this.NEWLINE_
    )
  }

  private appendImagesDescriptors(maxImagesCount: number): void {
    for (let i = 0; i < maxImagesCount; ++i) {
      this.columnDescriptors.set(`Image ${i + 1} Url`, {
        accessor: (product: Product) => product?.images[i]?.url ?? "",
        entityName: "product",
      })
    }
  }

  private appendOptionsDescriptors(maxOptionsCount: number): void {
    for (let i = 0; i < maxOptionsCount; ++i) {
      this.columnDescriptors
        .set(`Option ${i + 1} Name`, {
          accessor: (productOption: Product) =>
            productOption?.options[i]?.title ?? "",
          entityName: "product",
        })
        .set(`Option ${i + 1} Value`, {
          accessor: (variant: ProductVariant) =>
            variant?.options[i]?.value ?? "",
          entityName: "variant",
        })
    }
  }

  private appendMoneyAmountDescriptors(
    pricesData: ProductExportPriceData[]
  ): void {
    for (const priceData of pricesData) {
      if (priceData.currency_code) {
        this.columnDescriptors.set(
          `Price ${priceData.currency_code?.toUpperCase()} ${
            priceData.region?.id ? "(" + priceData.region?.id + ")" : ""
          }`,
          {
            accessor: (variant: ProductVariant) => {
              const price = variant.prices.find((variantPrice) => {
                let shouldReturnPrice = false
                if (variantPrice.currency_code) {
                  shouldReturnPrice =
                    !priceData.region &&
                    variantPrice.currency_code?.toLowerCase() ===
                      priceData.currency_code?.toLowerCase()
                }
                if (variantPrice.region) {
                  shouldReturnPrice =
                    variantPrice.region?.name?.toLowerCase() ===
                      priceData.region?.name?.toLowerCase() &&
                    variantPrice.region?.id?.toLowerCase() ===
                      priceData.region?.id?.toLowerCase()
                }
                return shouldReturnPrice
              })
              return price?.amount?.toString() ?? ""
            },
            entityName: "variant",
          }
        )
      }

      if (priceData.region) {
        this.columnDescriptors.set(
          `Price ${priceData.region.name.toLowerCase()} ${
            priceData.region?.id ? "(" + priceData.region?.id + ")" : ""
          }`,
          {
            accessor: (variant: ProductVariant) => {
              const price = variant.prices.find((variantPrice) => {
                return (
                  variantPrice.region?.name?.toLowerCase() ===
                    priceData.region?.name?.toLowerCase() &&
                  variantPrice.region?.id?.toLowerCase() ===
                    priceData.region?.id?.toLowerCase()
                )
              })
              return price?.amount?.toString() ?? ""
            },
            entityName: "variant",
          }
        )
      }
    }
  }

  private buildProductVariantLines(product: Product): string[] {
    const outputLineData: string[] = []

    for (const variant of product.variants) {
      const variantLineData: string[] = []
      for (const [, columnSchema] of this.columnDescriptors.entries()) {
        if (columnSchema.entityName === "product") {
          variantLineData.push(columnSchema.accessor(product))
        }
        if (columnSchema.entityName === "variant") {
          variantLineData.push(columnSchema.accessor(variant))
        }
      }
      outputLineData.push(variantLineData.join(this.DELIMITER_) + this.NEWLINE_)
    }

    return outputLineData
  }
}
