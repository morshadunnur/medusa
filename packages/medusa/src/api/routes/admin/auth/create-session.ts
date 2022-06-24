import { Request, Response } from "express"
import AbstractAuthStrategy from "../../../../interfaces/authentication-strategy"
import { MedusaError } from "medusa-core-utils"
import { AuthService, StrategyResolverService } from "../../../../services"
import { IsEmail, IsNotEmpty, IsString } from "class-validator"

/**
 * @oas [post] /auth
 * operationId: "PostAuth"
 * summary: "Authenticate a User"
 * x-authenticated: false
 * description: "Logs a User in and authorizes them to manage Store settings."
 * parameters:
 *   - (body) email=* {string} The User's email.
 *   - (body) password=* {string} The User's password.
 * tags:
 *   - Auth
 * responses:
 *  "200":
 *    description: OK
 *    content:
 *      application/json:
 *        schema:
 *          properties:
 *            user:
 *              $ref: "#/components/schemas/user"
 */
export default async (req: Request, res: Response) => {
  const authService = req.scope.resolve("authService") as AuthService
  const authStrategy = await authService.retrieveAuthenticationStrategy(
    req,
    "admin"
  )
  await authStrategy.authenticate(req, res)
}

export class AdminPostAuthReq {
  @IsEmail()
  @IsNotEmpty()
  email: string

  @IsString()
  @IsNotEmpty()
  password: string
}

