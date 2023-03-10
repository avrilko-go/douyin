import { IsNotEmpty, IsOptional, MaxLength } from 'class-validator';

import { DtoValidation } from '@/modules/core/decorators';

class Token {
    @IsNotEmpty()
    accessKeyId: string;

    @IsNotEmpty()
    secretAccessKey: string;

    @IsNotEmpty()
    sessionToken: string;
}

class Params {
    @IsNotEmpty()
    Action: string;

    @IsNotEmpty()
    Version: string;

    @IsNotEmpty()
    ServiceId: string;

    @IsOptional()
    app_id: string;

    @IsOptional()
    user_id = '';

    @IsOptional()
    s: string;

    @IsOptional()
    SessionKey: string;
}

@DtoValidation({
    type: 'body',
})
export class DouYinDto {
    @MaxLength(255, { always: true })
    @IsNotEmpty()
    method!: string;

    @IsNotEmpty()
    token!: Token;

    @IsNotEmpty()
    params!: Params;
}
