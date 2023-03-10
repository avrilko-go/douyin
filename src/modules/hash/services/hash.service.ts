import { Injectable } from '@nestjs/common';

@Injectable()
export class HashService {
    _hasher: any;

    _oKey: any;

    _iKey: any;

    init(e: any, t: any) {
        // eslint-disable-next-line no-param-reassign
        e = this._hasher = new e.init();

        const n = e.blockSize;
        const r = 4 * n;
        // eslint-disable-next-line no-param-reassign
        t.sigBytes > r && (t = e.finalize(t)), t.clamp();
        for (
            var i = (this._oKey = t.clone()),
                a = (this._iKey = t.clone()),
                A = i.words,
                s = a.words,
                c = 0;
            c < n;
            c++
        )
            (A[c] ^= 1549556828), (s[c] ^= 909522486);
        // eslint-disable-next-line block-scoped-var
        (i.sigBytes = a.sigBytes = r), this.reset();
        return this;
    }

    reset() {
        const e = this._hasher;
        // eslint-disable-next-line no-sequences
        e.reset(), e.update(this._iKey);
    }

    update(e: any) {
        this._hasher.update(e);
        return this;
    }

    finalize(e: any) {
        const t = this._hasher;
        const n = t.finalize(e);
        return t.reset(), t.finalize(this._oKey.clone().concat(n));
    }
}
