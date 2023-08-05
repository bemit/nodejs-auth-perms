import { AuthCanDo, AuthGrantsMapAbilities } from '@bemit/auth-perms/AuthCanDo'


export interface AuthGrantsIdentGrant<AT extends keyof any, A extends keyof any> {
    // todo: stricter typings could be replacing `string` with the actual attr value
    matches: { [ATTR in AT]: string | number | boolean | ((string | number)[]) | RegExp }
    abilities?: Extract<A, string>[]
    roles?: string[]
}

export interface AuthGrantsIdent<IDG extends AuthGrantsIdentGrant<string, string>> {
    blocked?: {
        byId?: string[]
        byEmail?: string[]
    }
    grants?: IDG[]
}

export interface AuthClaim {
    provider: string | 'anonym'
    sub?: string
    audience?: string
    email?: string

    // todo: maybe remove to be stricter, should be overridable easily
    [attr: string]: number | string | undefined
}

export type AuthGrantsGeneric = {
    roles: string[]
    abilities: string[]
}

export class AuthGrants<
    AC extends AuthClaim = AuthClaim,
    A extends AuthGrantsMapAbilities = AuthGrantsMapAbilities,
    IDG extends AuthGrantsIdentGrant<string, keyof A> = AuthGrantsIdentGrant<string, keyof A>,
    I extends AuthGrantsIdent<IDG> = AuthGrantsIdent<IDG>
> {
    protected readonly canDo: AuthCanDo<A>
    protected ident: I

    constructor(
        canDo: AuthCanDo<A>,
        ident: I,
    ) {
        this.canDo = canDo
        this.ident = ident
    }

    updateIdentificationRules(ident: AuthGrants<AC, A, IDG, I>['ident']) {
        this.ident = ident
    }

    isBlocked(ident: { id?: string, email?: string }) {
        return (
            (ident.id && this.ident.blocked?.byId?.includes(ident.id)) ||
            (ident.email && this.ident.blocked?.byEmail?.includes(ident.email))
        )
    }

    resolveClaims(
        claim: AC,
        options?: {
            expandRoles?: boolean
        },
    ): { scopes: string[] } {
        const granted = this.processClaim(claim)

        const grantReducers: ((
            grantedInfo: {
                scopes: { [scope: string]: any }
            },
            grant: IDG,
        ) => {
            scopes: { [scope: string]: any }
        })[] = [
            (grantedInfo, grant) => grant.roles?.reduce((grantedInfo, role) => {
                const roleSpec = this.canDo.role(role)
                return {
                    ...grantedInfo,
                    scopes: {
                        ...grantedInfo.scopes,
                        [roleSpec.scope]: {},
                        ...options?.expandRoles ?
                            roleSpec.abilities?.reduce((grantedInfo, ability) => ({
                                ...grantedInfo,
                                [this.canDo.abilityToScope(ability)]: {},
                            }), {}) || {} : {},
                    },
                }
            }, grantedInfo) || grantedInfo,
            (grantedInfo, grant) => grant.abilities?.reduce((grantedInfo, ability) => ({
                ...grantedInfo,
                scopes: {
                    ...grantedInfo.scopes,
                    [this.canDo.abilityToScope(
                        typeof ability === 'string' ? ability : ability[0],
                    )]: {},
                },
            }), grantedInfo) || grantedInfo,
        ]

        const grantedInfo = granted?.reduce<{
            scopes: { [scope: string]: any }
        }>((scopes, grant) => {
            for(const reducer of grantReducers) {
                scopes = reducer(scopes, grant)
            }

            return scopes
        }, {scopes: {}})

        return {
            scopes: Object.keys(grantedInfo?.scopes || {}),
        }
    }

    simulate(claim: AC): {
        scopes: string[]
        grants: {
            roles: string[]
            // roles: Extract<keyof R, string>[]
            abilities: Extract<keyof A, string>[]
        }
    } {
        const grantedScopes = this.resolveClaims(claim)
        return {
            scopes: grantedScopes.scopes,
            grants: this.canDo.resolveGrants({scopes: grantedScopes.scopes}),
        }
    }

    protected processClaim(claim: AC): IDG[] | undefined {
        return this.ident.grants?.reduce((granted, grant) => {
            const matchAttrs = Object.keys(grant.matches)
            let validMatches = 0
            for(const attr of matchAttrs) {
                const attrMatch = grant.matches[attr]
                const attrVal = claim[attr]
                if(typeof attrVal === 'undefined') continue
                if(
                    typeof attrMatch === 'string' ||
                    typeof attrMatch === 'number' ||
                    typeof attrMatch === 'boolean'
                ) {
                    if(attrMatch === attrVal) {
                        validMatches++
                    }
                } else if(Array.isArray(attrMatch)) {
                    if(attrMatch.includes(attrVal)) {
                        validMatches++
                    }
                } else if(attrMatch.test(typeof attrVal === 'string' ? attrVal : String(attrVal))) {
                    validMatches++
                }
            }
            if(validMatches === matchAttrs.length) {
                granted.push(grant as IDG)
            }
            return granted
        }, [] as IDG[])
    }

    getRuleOfRole(role: string) {
        return this.canDo.role(role)
    }
}
