export type AuthGrantsMapAbilities<A extends keyof any = keyof any> = {
    [K in A]: {}
}

export interface AuthGrantsMapRoles<A extends keyof any> {
    [role: string]: {
        label?: string
        scope: string
        abilities?: (Extract<A, string>)[]
    }
}


export interface AuthCanDoRules<A extends {}> {
    abilityToScope: <AID extends Extract<keyof A, string>>(ability: AID) => string
    roles: AuthGrantsMapRoles<keyof A>
}

export type AuthGrantsGiven<ACD extends AuthCanDo> = {
    roles: string[]
    abilities: Extract<keyof (ACD extends AuthCanDo<infer A> ? A : never), string>[]
}

export class AuthCanDo<A extends AuthGrantsMapAbilities = AuthGrantsMapAbilities> {
    protected readonly rules: AuthCanDoRules<A>
    protected readonly abilities: AuthGrantsMapAbilities<keyof A>
    protected readonly rolesList: Extract<keyof AuthGrantsMapRoles<keyof A>, string>[] = []
    protected readonly abilitiesList: Extract<keyof A, string>[] = []

    protected scopeMap: {
        [scope: string]: {
            roles: Extract<keyof AuthGrantsMapRoles<keyof A>, string>[]
            abilities: Extract<keyof A, string>[]
        }
    } = {}

    constructor(
        abilities: AuthGrantsMapAbilities<keyof A>,
        canDoRules: AuthCanDoRules<A>,
    ) {
        this.abilities = abilities
        this.rules = canDoRules
        this.abilitiesList = Object.keys(abilities) as Extract<keyof A, string>[]
        this.rolesList = Object.keys(canDoRules.roles) as Extract<keyof AuthGrantsMapRoles<keyof A>, string>[]
        this.scopeMap = AuthCanDo.buildScopeMap<A>(
            this.abilities,
            this.rules.abilityToScope,
            this.rules.roles,
        )
    }

    protected static buildScopeMap<A extends AuthGrantsMapAbilities>(
        abilities: AuthGrantsMapAbilities<keyof A>,
        abilityToScope: AuthCanDoRules<A>['abilityToScope'],
        roles: AuthGrantsMapRoles<keyof A>,
    ) {
        const scopeMap: AuthCanDo<A>['scopeMap'] = {}
        const initScope = (scope: string) => {
            if(scopeMap[scope]) {
                throw new Error('AuthGrants duplicate scope detected')
            }
            scopeMap[scope] = {
                roles: [],
                abilities: [],
            }
        }
        const abilitiesList = Object.keys(abilities) as Extract<keyof A, string>[]
        const rolesList = Object.keys(roles) as string[]
        abilitiesList.map(abilityId => {
            const scope = abilityToScope(abilityId)
            initScope(scope)
            scopeMap[scope].abilities.push(abilityId)
        })
        rolesList.map(role => {
            const roleSpec = roles[role]
            const scope = roleSpec.scope
            initScope(scope)
            scopeMap[scope].roles.push(role)
            if(roleSpec.abilities) {
                scopeMap[scope].abilities.push(...roleSpec.abilities)
            }
        })
        return scopeMap
    }

    updateScopeRules(rules: Omit<AuthCanDoRules<A>, 'abilityToScope'> & Pick<Partial<AuthCanDoRules<A>>, 'abilityToScope'>) {
        this.rules.abilityToScope = rules.abilityToScope || this.rules.abilityToScope
        this.rules.roles = rules.roles
        this.scopeMap = AuthCanDo.buildScopeMap<A>(
            this.abilities,
            this.rules.abilityToScope,
            rules.roles,
        )
    }

    role(roleId: string) {
        const role = this.rules.roles[roleId]
        if(!role) {
            throw new Error(`role "${roleId}" does not exist`)
        }
        return role
    }

    abilityToScope: AuthCanDoRules<A>['abilityToScope'] = (ability) => {
        return this.rules.abilityToScope(ability)
    }

    resolveGrants({scopes}: { scopes: string[] | undefined }): {
        roles: string[]
        abilities: Extract<keyof A, string>[]
    } {
        // todo: the authGrant "matching" only works for JWTs generated from this service;
        //       but can't add roles depending on `audience` when using and IDM for JWTs
        // todo: anonym must be supported here - not only at the token
        const granted = scopes?.map(scope => this.scopeMap[scope]).filter(s => s).reduce<{
            roles: { [ROLE in string]?: any }
            abilities: { [ABILITY in Extract<keyof A, string>]?: any }
        }>((granted, scope) => ({
            ...granted,
            abilities: {
                ...granted.abilities,
                ...scope.abilities.reduce((abilities, ability) => ({
                    ...abilities,
                    [ability]: {},
                }), {}),
            },
            roles: {
                ...granted.roles,
                ...scope.roles.reduce((roles, role) => ({
                    ...roles,
                    [role]: {},
                }), {}),
            },
        }), {roles: {}, abilities: {}})
        return {
            roles: Object.keys(granted?.roles || {}) as string[],
            abilities: Object.keys(granted?.abilities || {}) as Extract<keyof A, string>[],
        }
    }


    existRole(role: string): string | undefined {
        return this.rolesList.includes(role) ? role : undefined
    }

    existAbility(ability: Extract<keyof A, string> | string): Extract<keyof A, string> | undefined {
        return this.abilitiesList.includes(ability as Extract<keyof A, string>) ? ability as Extract<keyof A, string> : undefined
    }
}
