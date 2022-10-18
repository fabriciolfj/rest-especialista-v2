# rest-especialista-v2

## Atualização do spring authorization server
- O antigo spring oauth2 foi quebrado em 2 projetos:
  - spring security (aonde encontra-se o resources server)
  - spring authorization server (responsável pela geração e validação do token)
    - precisamos de um filter SecurityFilterChain
    - um bean provider ProviderSettings
    - um repositório dos clients -> RegisteredClientRepository
    - um local para persistir o token -> OAuth2AuthorizationService
  - não precisamos mais extender a classe WebSecurityConfigurerAdapter
  - toda a configuração e feita via beans

### novos endpotins
- {{baseURL}}/oauth2/token
- {{baseURL}}/oauth2/introspect
- {{baseURL}}/oauth2/revoke
- para o authorization code, precisamos passar mais alguns parâmetros (como request parameter), por exemplo:
  - {{baseURL}}/oauth2/authorize?response_type=code&client_id=algafood-web&state=abc&redirect_uri=http://localhost:9090/authorized&scope=READ WRITE&code_challenge=bKE9UspwyIPg8LsQHkJaiehiTeUdstI5JZOvaoQRgJA&code_challenge_method=S256
  - para gerar o code_challenge, utilize o site https://tonyxu-io.github.io/pkce-generator

### Personalizando um token jwt
- abaixo um exemplo no authorization server
```
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(final UsuarioRepository usuarioRepository) {
        return context -> {
            Authentication authentication = context.getPrincipal();

            if (authentication.getPrincipal() instanceof User) {
                final User user = (User) authentication.getPrincipal();
                final Usuario usuario = usuarioRepository.findByEmail(user.getUsername()).orElseThrow();

                final Set<String> authorities = new HashSet<>();
                for (GrantedAuthority auth : user.getAuthorities()) {
                    authorities.add(auth.getAuthority());
                }

                context.getClaims().claim("usuario_id", usuario.getId().toString());
                context.getClaims().claim("authorities", authorities);
            }
        };
    }
```
- abaixo um exemplo no resource server
```
                .oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter());

        return http.formLogin(Customizer.withDefaults()).build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = jwt.getClaimAsStringList("authorities");

            if (authorities == null) {
                return Collections.emptyList();
            }

            var authoritiesGranted = new JwtGrantedAuthoritiesConverter();
            var grantedAuthorities = authoritiesGranted.convert(jwt);

            grantedAuthorities.addAll(authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

            return grantedAuthorities;
        });

        return converter;
    }
```