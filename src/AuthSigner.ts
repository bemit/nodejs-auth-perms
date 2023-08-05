export interface AppAuthSignInfo {
    idToken: string | undefined
    accessToken: string
}

export class AuthSigner<E extends {} = {}, E2 extends E = E> {
    protected readonly signSteps: ((signInfo: any) => Promise<any>)[] = []
    protected readonly signInfo: E

    constructor(signInfo: E) {
        this.signInfo = signInfo
    }

    with<P extends {}, E3 extends E2 & P = E2 & P>(
        signStep: <SI extends E2>(signInfo: SI) => Promise<E3>,
    ): AuthSigner<E, E3> {
        this.signSteps.push(signStep)
        return this as unknown as AuthSigner<E, E3>
    }

    async run(): Promise<E2> {
        let signInfo: E = this.signInfo
        for(const signStep of this.signSteps) {
            signInfo = await signStep(signInfo)
        }
        return signInfo as E2
    }
}
