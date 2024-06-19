import { HttpException, Inject, Injectable } from "@nestjs/common";
import { WINSTON_MODULE_PROVIDER } from "nest-winston";
import { PrismaService } from "../common/prisma.service";
import { ValidationService } from "../common/validation.service";
import { LoginUserRequest, RegisterUserRequest, UserResponse } from "../model/user.model";
import { Logger, exceptions } from "winston";
import { UserValidation } from "./user.validation";
import * as bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";

@Injectable()
export class UserService {

    constructor(
        private validationService: ValidationService,
        @Inject(WINSTON_MODULE_PROVIDER) private logger: Logger,
        private prismaService:PrismaService

    ){}
    
    async register(request: RegisterUserRequest) : Promise<UserResponse>{

        this.logger.info(`Register new user ${JSON.stringify(request)}`)
        
        const registerRequest: RegisterUserRequest = this.validationService.validate(UserValidation.REGISTER, request)
        
        const totalUsernameWithSameUsername = await this.prismaService.user.count({
            where: {
                username: registerRequest.username
            }
        })

        if(totalUsernameWithSameUsername != 0){
            throw new HttpException('username already exists', 400)
        }
        
        registerRequest.password = await bcrypt.hash(registerRequest.password, 10)

        const user = await this.prismaService.user.create({
            data: registerRequest
        })

        return {
            username: user.username,
            name: user.name
        }
    }

    async login(request: LoginUserRequest): Promise<UserResponse>{
        this.logger.info(`user service login(${JSON.stringify(request)})`)
        const loginRequest: LoginUserRequest = this.validationService.validate(UserValidation.LOGIN, request)

        //cek apaakah usernya ada
        let user = await this.prismaService.user.findUnique({
            where : {
                username: loginRequest.username
            }
        })

        //jika tidak ada username
        if(!user) {
            throw new HttpException('username or password is invalid', 401)
        }

        //jika user ada maka cek password dengan bcrypt
        const isPasswordValid = await bcrypt.compare(
            loginRequest.password,
            user.password
        )

        //jika password tidak valid
        if(!isPasswordValid) {
            throw new HttpException('username or password is invalid', 401)
        }

        user = await this.prismaService.user.update({
            where: {
                username: loginRequest.username
            },
            data: {
                token: uuid()
            }
        })

        return {
            username: user.username,
            name: user.name,
            token: user.token
        }


        return null
    }

}