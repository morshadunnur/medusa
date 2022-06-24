import { AuthService } from "../../../../services"
import { Request, Response } from "express"
import { IsEmail, IsNotEmpty } from "class-validator"

/**
 * @oas [post] /auth
 * operationId: "PostAuth"
 * summary: "Authenticate Customer"
 * description: "Logs a Customer in and authorizes them to view their details. Successful authentication will set a session cookie in the Customer's browser."
 * parameters:
 *   - (body) email=* {string} The Customer's email.
 *   - (body) password=* {string} The Customer's password.
 * tags:
 *   - Auth
 * responses:
 *  "200":
 *    description: OK
 *    content:
 *      application/json:
 *        schema:
 *          properties:
 *            customer:
 *              $ref: "#/components/schemas/customer"
 */
export default async (req: Request, res: Response) => {
  const authService = req.scope.resolve("authService") as AuthService
  const authStrategy = await authService.retrieveAuthenticationStrategy(
    req,
    "store"
  )
  await authStrategy.authenticate(req, res)
}

export class StorePostAuthReq {
  @IsEmail()
  email: string

  @IsNotEmpty()
  password: string
}
