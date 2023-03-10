import { Module } from '@nestjs/common';

import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';

import { AppFilter } from '@/modules/core/providers/app.filter';
import { AppInterceptor } from '@/modules/core/providers/app.interceptor';
import { AppPipe } from '@/modules/core/providers/app.pipe';
import { HashModule } from '@/modules/hash/hash.module';

@Module({
    imports: [HashModule],
    controllers: [],
    providers: [
        {
            provide: APP_PIPE,
            useValue: new AppPipe({
                transform: true,
                forbidUnknownValues: true,
                validationError: { target: false },
            }),
        },
        {
            provide: APP_INTERCEPTOR,
            useClass: AppInterceptor,
        },
        {
            provide: APP_FILTER,
            useClass: AppFilter,
        },
    ],
})
export class AppModule {}
