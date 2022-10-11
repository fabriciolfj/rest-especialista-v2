# rest-especialista-v2

## Atualização do spring authorization server
- O antigo spring oauth2 foi quebrado em 2 projetos:
  - spring security (aonde encontra-se o resources server)
  - spring authorization server (responsável pela geração e validação do token)
  - não precisamos mais extender a classe WebSecurityConfigurerAdapter
  - toda a configuração e feita via beans

### novos endpotins
- {{baseURL}}/oauth2/token
- {{baseURL}}/oauth2/introspect
- {{baseURL}}/oauth2/revoke