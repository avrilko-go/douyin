import { Module } from '@nestjs/common';

import { HashService } from '@/hash.service';

import { AppController } from './app.controller';
import { AppService } from './app.service';

@Module({
    imports: [],
    controllers: [AppController],
    providers: [AppService, HashService],
})
export class AppModule {}
