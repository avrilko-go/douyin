import { Injectable } from '@nestjs/common';

import { DouyinService } from '@/modules/hash/services/douyin.service';

@Injectable()
export class PostService {
    constructor(protected douyinService: DouyinService) {}

    async getDouyinToken() {}
}
