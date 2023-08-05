import { AuthRuleError } from '@bemit/auth-perms/AuthRuleError'
import { AuthGrantsGeneric } from '@bemit/auth-perms/AuthGrants'

export interface AuthValidatorTokenBase {
    sub: string
    aud: string
}

export interface AuthValidatorTokenScoped extends AuthValidatorTokenBase {
    scope: string
}

export interface AuthValidatorIdentClaim<AVT extends Partial<AuthValidatorTokenBase>, AG extends AuthGrantsGeneric> {
    authId: AVT
    authGrants: AG
}

export function noAnonym<AP extends Partial<AuthValidatorTokenBase> = Partial<AuthValidatorTokenBase>>(authId: AP | undefined): asserts authId is AP & AuthValidatorTokenBase {
    if(!authId) {
        throw new AuthRuleError('no-anonym-access').setCode(401)
    }

    if(!authId.aud) {
        throw new AuthRuleError('authentication-invalid')
            .setCode(401)
            .withConstraint({message: 'audience is missing', rule: 'aud'})
    }
    if(!authId.sub) {
        throw new AuthRuleError('authentication-invalid')
            .setCode(401)
            .withConstraint({message: 'issued subject is missing', rule: 'sub'})
    }
}

export const AuthValidator: {
    noAnonym: <AP extends Partial<AuthValidatorTokenBase> = Partial<AuthValidatorTokenBase>>(authId: AP | undefined) =>
        asserts authId is AP & AuthValidatorTokenBase
    hasScope: <AP extends Partial<AuthValidatorTokenScoped> = Partial<AuthValidatorTokenScoped>>(authId: AP | undefined, ...scope: string[]) =>
        asserts authId is AP & AuthValidatorTokenScoped
    // todo: `hasRole` and `hasAbility` enforce `authId` and thus "not-anonym", but both would also need to work for anonym
    hasRole: <AVT extends Partial<AuthValidatorTokenBase>, AG extends AuthGrantsGeneric>(identClaim: { authId?: AVT, authGrants?: AG } | undefined, ...roles: AG['roles']) =>
        asserts identClaim is
            { authId: AVT } &
            AuthValidatorIdentClaim<AuthValidatorTokenBase, AG>
    hasAbility: <AVT extends Partial<AuthValidatorTokenBase>, AG extends AuthGrantsGeneric>(identClaim: { authId?: AVT, authGrants?: AG } | undefined, ...abilities: AG['abilities']) =>
        asserts identClaim is
            { authId: AVT } &
            AuthValidatorIdentClaim<AuthValidatorTokenBase, AG>
} = {
    noAnonym: noAnonym,
    hasScope: <AP extends Partial<AuthValidatorTokenScoped> = Partial<AuthValidatorTokenScoped>>(authId: AP | undefined, ...scopes: string[]): asserts authId is AP & AuthValidatorTokenScoped => {
        const authIdScopes = authId?.scope?.split(' ')
        if(!authIdScopes || !scopes.find(s => authIdScopes?.includes(s))) {
            throw new AuthRuleError('access-not-granted')
                .setCode(403)
                .withConstraint({
                    message: 'requires one of scopes: ' + scopes.join(', '),
                    rule: 'scope-contains',
                })
        }
    },
    hasRole: <AVT extends Partial<AuthValidatorTokenBase>, AG extends AuthGrantsGeneric>(identClaim: { authId?: AVT, authGrants?: AG } | undefined, ...roles: AG['roles']): asserts identClaim is { authId: AVT } & AuthValidatorIdentClaim<AuthValidatorTokenBase, AG> => {
        noAnonym(identClaim?.authId)
        const claimRoles = identClaim.authGrants?.roles
        if(!claimRoles || !roles.find(s => claimRoles.includes(s))) {
            throw new AuthRuleError('access-not-granted')
                .setCode(401)
                .withConstraint({
                    message: 'requires one of roles: ' + roles.join(', '),
                    rule: 'roles-contains',
                })
        }
    },
    hasAbility: <AVT extends Partial<AuthValidatorTokenBase>, AG extends AuthGrantsGeneric>(identClaim: { authId?: AVT, authGrants?: AG } | undefined, ...abilities: AG['abilities']): asserts identClaim is { authId: AVT } & AuthValidatorIdentClaim<AuthValidatorTokenBase, AG> => {
        noAnonym(identClaim?.authId)
        const claimAbilities = identClaim.authGrants?.abilities
        if(!claimAbilities || !abilities.find(s => claimAbilities.includes(s))) {
            throw new AuthRuleError('access-not-granted')
                .setCode(401)
                .withConstraint({
                    message: 'requires one of abilities: ' + abilities.join(', '),
                    rule: 'abilities-contains',
                })
        }
    },
}
