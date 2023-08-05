import { AuthSigner } from '@bemit/auth-perms/AuthSigner'
import { AuthGrants } from '@bemit/auth-perms/AuthGrants'
import { AuthCanDo } from '@bemit/auth-perms/AuthCanDo'

export class AppAuth<ACD extends AuthCanDo, AG extends AuthGrants | undefined = AuthGrants | undefined> {
    public readonly authCanDo: ACD
    public readonly authGrants?: AG

    constructor(authCanDo: ACD, authGrants?: AG) {
        this.authCanDo = authCanDo
        this.authGrants = authGrants
    }

    trySign<AI extends {} = {}>(signInfo: AI) {
        return new AuthSigner<AI>(signInfo)
    }
}
