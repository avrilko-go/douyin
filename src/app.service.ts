import { Injectable } from '@nestjs/common';
import hmac from 'crypto-js/hmac-sha256';
import sha256 from 'crypto-js/sha256';

@Injectable()
export class AppService {
    method = 'get';

    auth = [
        'authorization',
        'content-type',
        'content-length',
        'user-agent',
        'presigned-expires',
        'expect',
        'x-amzn-trace-id',
    ];

    headers = {
        Authorization: '',
        'X-Amz-Content-Sha256': '',
    };

    params = {
        Action: 'ApplyImageUpload',
        Version: '2018-08-01',
        ServiceId: 'jm8ajry58r',
        app_id: 2906,
        user_id: '',
        s: 'plvu10aphdm',
    };

    body = {};

    token: {
        accessKeyId: 'AKTPZTI1NWZjNmE4NGVjNDk3NDhlNmI2NjU4MTg3MDYyOWY';
        secretAccessKey: 'cJ7WUV0HMXPUmQTFguOtZahwxDn5VAnQ9s0AtWJYrRLgFVUunpvLXEY/7t6rw2bS';
        sessionToken: 'STS2eyJMVEFjY2Vzc0tleUlEIjoiQUtMVFlqZGpZVFV3WldRd1pEVTBORFJtTW1Fd05XVTVObUUxTVRkaVl6VXlaVGciLCJBY2Nlc3NLZXlJRCI6IkFLVFBaVEkxTldaak5tRTROR1ZqTkRrM05EaGxObUkyTmpVNE1UZzNNRFl5T1dZIiwiU2lnbmVkU2VjcmV0QWNjZXNzS2V5IjoiY1ZVSHc2eUZHRjZOeFlwRGZNcVVLVjY3ZzI2eHppRm9HWWxHY1pHYUhTMUNtaGg1UnJwYXo3ZDc4ajdwWklaQXhzS2VhUnZOUzRLZXdoTThNOFhpbFFtUmFoWldVQzNZdEE4cS92cXZMNWs9IiwiRXhwaXJlZFRpbWUiOjE2Nzg0MzMwMTMsIlBvbGljeVN0cmluZyI6IntcIlN0YXRlbWVudFwiOlt7XCJFZmZlY3RcIjpcIkFsbG93XCIsXCJBY3Rpb25cIjpbXCJ2b2Q6KlwiLFwiSW1hZ2VYOipcIl0sXCJSZXNvdXJjZVwiOltcIipcIl19LHtcIkVmZmVjdFwiOlwiQWxsb3dcIixcIkFjdGlvblwiOltcIlVzZXJJZFwiXSxcIlJlc291cmNlXCI6W1wiMTAyODQyNjYwMDQ3XCJdfSx7XCJFZmZlY3RcIjpcIkFsbG93XCIsXCJBY3Rpb25cIjpbXCJBcHBJZFwiXSxcIlJlc291cmNlXCI6W1wiMTEyOFwiXX0se1wiRWZmZWN0XCI6XCJBbGxvd1wiLFwiQWN0aW9uXCI6W1wiVXNlclJlZmVyZW5jZVwiXSxcIlJlc291cmNlXCI6W1wie1xcXCJwc21cXFwiOlxcXCJkb3V5aW4uY3JlYXRvci5jb250ZW50XFxcIn1cIl19LHtcIkVmZmVjdFwiOlwiQWxsb3dcIixcIkFjdGlvblwiOltcIlNlc3Npb25DaGVja1wiXSxcIlJlc291cmNlXCI6W1wiVWlkXCJdfSx7XCJFZmZlY3RcIjpcIkFsbG93XCIsXCJBY3Rpb25cIjpbXCJQU01cIl0sXCJSZXNvdXJjZVwiOltcImRvdXlpbi5jcmVhdG9yLmNvbnRlbnRcIl19XX0iLCJTaWduYXR1cmUiOiJhYjI3M2U1OGNlMDJjYzUyMjZmNGQ5NDNkMzMyNTFhM2Y5YTBmNzQ0NjlmZmU5NTliZTFmNjk0NGI5OWFjNDAwIn0=';
    };

    // "AWS4-HMAC-SHA256 Credential=AKTPZTI1NWZjNmE4NGVjNDk3NDhlNmI2NjU4MTg3MDYyOWY/20230308/cn-north-1/imagex/aws4_request, SignedHeaders=x-amz-date;x-amz-security-token, Signature=393fcda130d7a793a5de96ecd72871a1c8a9491a04318786e067dea440e1e4e0"

    getHello(): string {
        this.method = 'get';
        this.auth = [
            'authorization',
            'content-type',
            'content-length',
            'user-agent',
            'presigned-expires',
            'expect',
            'x-amzn-trace-id',
        ];
        this.params = {
            Action: 'ApplyImageUpload',
            Version: '2018-08-01',
            ServiceId: 'jm8ajry58r',
            app_id: 2906,
            user_id: '',
            s: 'plvu10aphdm',
        };
        this.token = {
            accessKeyId: 'AKTPZTI1NWZjNmE4NGVjNDk3NDhlNmI2NjU4MTg3MDYyOWY',
            secretAccessKey: 'cJ7WUV0HMXPUmQTFguOtZahwxDn5VAnQ9s0AtWJYrRLgFVUunpvLXEY/7t6rw2bS',
            sessionToken:
                'STS2eyJMVEFjY2Vzc0tleUlEIjoiQUtMVFlqZGpZVFV3WldRd1pEVTBORFJtTW1Fd05XVTVObUUxTVRkaVl6VXlaVGciLCJBY2Nlc3NLZXlJRCI6IkFLVFBaVEkxTldaak5tRTROR1ZqTkRrM05EaGxObUkyTmpVNE1UZzNNRFl5T1dZIiwiU2lnbmVkU2VjcmV0QWNjZXNzS2V5IjoiY1ZVSHc2eUZHRjZOeFlwRGZNcVVLVjY3ZzI2eHppRm9HWWxHY1pHYUhTMUNtaGg1UnJwYXo3ZDc4ajdwWklaQXhzS2VhUnZOUzRLZXdoTThNOFhpbFFtUmFoWldVQzNZdEE4cS92cXZMNWs9IiwiRXhwaXJlZFRpbWUiOjE2Nzg0MzMwMTMsIlBvbGljeVN0cmluZyI6IntcIlN0YXRlbWVudFwiOlt7XCJFZmZlY3RcIjpcIkFsbG93XCIsXCJBY3Rpb25cIjpbXCJ2b2Q6KlwiLFwiSW1hZ2VYOipcIl0sXCJSZXNvdXJjZVwiOltcIipcIl19LHtcIkVmZmVjdFwiOlwiQWxsb3dcIixcIkFjdGlvblwiOltcIlVzZXJJZFwiXSxcIlJlc291cmNlXCI6W1wiMTAyODQyNjYwMDQ3XCJdfSx7XCJFZmZlY3RcIjpcIkFsbG93XCIsXCJBY3Rpb25cIjpbXCJBcHBJZFwiXSxcIlJlc291cmNlXCI6W1wiMTEyOFwiXX0se1wiRWZmZWN0XCI6XCJBbGxvd1wiLFwiQWN0aW9uXCI6W1wiVXNlclJlZmVyZW5jZVwiXSxcIlJlc291cmNlXCI6W1wie1xcXCJwc21cXFwiOlxcXCJkb3V5aW4uY3JlYXRvci5jb250ZW50XFxcIn1cIl19LHtcIkVmZmVjdFwiOlwiQWxsb3dcIixcIkFjdGlvblwiOltcIlNlc3Npb25DaGVja1wiXSxcIlJlc291cmNlXCI6W1wiVWlkXCJdfSx7XCJFZmZlY3RcIjpcIkFsbG93XCIsXCJBY3Rpb25cIjpbXCJQU01cIl0sXCJSZXNvdXJjZVwiOltcImRvdXlpbi5jcmVhdG9yLmNvbnRlbnRcIl19XX0iLCJTaWduYXR1cmUiOiJhYjI3M2U1OGNlMDJjYzUyMjZmNGQ5NDNkMzMyNTFhM2Y5YTBmNzQ0NjlmZmU5NTliZTFmNjk0NGI5OWFjNDAwIn0=',
        };

        this.addAuthorization(new Date('Wed Mar 08 2023 15:23:33 GMT+0800 (中国标准时间)'));
        console.log(this.headers);
        return '111';
        // 393fcda130d7a793a5de96ecd72871a1c8a9491a04318786e067dea440e1e4e0
    }

    addAuthorization(t: any) {
        const n = this.iso8601(t).replace(/[:-]|\.\d{3}/g, '');
        this.addHeaders(this.token, n);
        this.headers.Authorization = this.authorization(this.token, n);
    }

    iso8601(e: Date) {
        return e.toISOString().replace(/\.\d{3}Z$/, 'Z');
    }

    addHeaders(e: any, t: string) {
        // @ts-ignore
        // @ts-ignore
        // @ts-ignore
        this.headers['X-Amz-Date'] = t;
        // @ts-ignore
        e.sessionToken && (this.headers['x-amz-security-token'] = e.sessionToken);
        // @ts-ignore
        if (this.body) {
            // @ts-ignore
            this.headers['X-Amz-Content-Sha256'] = sha256(JSON.stringify(this.body)).toString();
        }
    }

    authorization(e: any, t: string) {
        const n = [];
        const r = this.credentialString(t);
        return (
            n.push(
                ''.concat('AWS4-HMAC-SHA256', ' Credential=').concat(e.accessKeyId, '/').concat(r),
            ),
            n.push('SignedHeaders='.concat(this.signedHeaders())),
            n.push('Signature='.concat(this.signature(e, t))),
            n.join(', ')
        );
    }

    signature(e: any, t: any) {
        const n = this.getSigningKey(e, t.substr(0, 8), 'cn-north-1', 'imagex');
        return hmac(n, this.stringToSign(t)).toString();
    }

    stringToSign(e: any) {
        const t = [];
        return (
            t.push('AWS4-HMAC-SHA256'),
            t.push(e),
            t.push(this.credentialString(e)),
            t.push(sha256(this.canonicalString())),
            t.join('\n')
        );
    }

    canonicalString() {
        const e = [];
        const t = '/';
        return (
            e.push(this.method.toUpperCase()),
            e.push(t),
            e.push(this.u(this.params) || ''),
            e.push(''.concat(this.canonicalHeaders(), '\n')),
            e.push(this.signedHeaders()),
            e.push(this.hexEncodedBodyHash()),
            e.join('\n')
        );
    }

    hexEncodedBodyHash() {
        // eslint-disable-next-line no-nested-ternary
        return this.headers['X-Amz-Content-Sha256']
            ? this.headers['X-Amz-Content-Sha256']
            : this.body
            ? sha256(this.u(this.body))
            : sha256('');
    }

    u(e: any) {
        const that = this;
        return (
            Object.keys(e)
                .sort()
                // eslint-disable-next-line array-callback-return
                .map(function (t) {
                    const n = e[t];
                    if (n != null) {
                        const r = that.l(t);
                        if (r) {
                            return Array.isArray(n)
                                ? ''.concat(r, '=').concat(
                                      n
                                          .map(function (eee) {
                                              return that.l(eee);
                                          })
                                          .sort()
                                          .join('&'.concat(r, '=')),
                                  )
                                : ''.concat(r, '=').concat(that.l(n));
                        }
                        return '';
                    }
                    return '';
                })
                .filter(function (eee: any) {
                    return eee;
                })
                .join('&')
        );
    }

    l(e: any) {
        try {
            return encodeURIComponent(e)
                .replace(/[^A-Za-z0-9_.~\-%]+/g, escape)
                .replace(/[*]/g, function (ee: any) {
                    return '%'.concat(ee.charCodeAt(0).toString(16).toUpperCase());
                });
        } catch (eee) {
            return '';
        }
    }

    canonicalHeaders() {
        const e = this;
        const t: any = [];
        Object.keys(this.headers).forEach(function (n) {
            // @ts-ignore
            t.push([n, e.headers[n]]);
        }),
            t.sort(function (ee: any, tt: any) {
                return ee[0].toLowerCase() < tt[0].toLowerCase() ? -1 : 1;
            });
        const n: any = [];
        return (
            t.forEach(function (ttt: any) {
                const r = ttt[0].toLowerCase();
                if (e.isSignableHeader(r)) {
                    const i = ttt[1];
                    if (i == null || typeof i.toString !== 'function')
                        throw new Error('Header '.concat(r, ' contains invalid value'));
                    n.push(''.concat(r, ':').concat(e.canonicalHeaderValues(i.toString())));
                }
            }),
            n.join('\n')
        );
    }

    canonicalHeaderValues(e: any) {
        return e.replace(/\s+/g, ' ').replace(/^\s+|\s+$/g, '');
    }

    getSigningKey(e: any, t: any, n: any, r: any) {
        const i = this.hmacF('AWS4'.concat(e.secretAccessKey), t);
        const o = this.hmacF(i, n);
        const A = this.hmacF(o, r);
        return this.hmacF(A, 'aws4_request');
    }

    hmacF(a: any, b: any) {
        return hmac(b, a);
    }

    signedHeaders() {
        const e = this;
        const t: any = [];
        return (
            Object.keys(this.headers).forEach(function (n) {
                // eslint-disable-next-line no-param-reassign
                n = n.toLowerCase();
                e.isSignableHeader(n) && t.push(n);
            }),
            t.sort().join(';')
        );
    }

    isSignableHeader(e: string) {
        return e.toLowerCase().indexOf('x-amz-') === 0 || this.auth.indexOf(e) < 0;
    }

    credentialString(e: string) {
        return this.createScope(e.substr(0, 8), 'cn-north-1', 'imagex');
    }

    createScope(e: string, t: string, n: string) {
        return [e.substr(0, 8), t, n, 'aws4_request'].join('/');
    }
}
