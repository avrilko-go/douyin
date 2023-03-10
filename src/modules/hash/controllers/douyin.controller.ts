import { Body, Controller, Post, SerializeOptions, UseInterceptors } from '@nestjs/common';

import { AppInterceptor } from '@/modules/core/providers/app.interceptor';
import { DouYinDto } from '@/modules/dtos';
import { DouyinService } from '@/modules/hash/services';

@UseInterceptors(AppInterceptor)
@Controller('douyin')
export class DouyinController {
    constructor(protected douyinService: DouyinService) {}

    @SerializeOptions({})
    @Post()
    async create(
        @Body()
        data: DouYinDto,
    ) {
        return this.douyinService.computeHash(data);
    }
}
