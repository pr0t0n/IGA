# Nexo IGA

Plataforma funcional de Identity Governance & Administration multi-cloud. A solução possui frontend Nginx, API FastAPI, autenticação por perfis e PostgreSQL com credenciais criptografadas.

## Executar com Docker (recomendado)

```bash
cp .env.example .env
# Edite todas as senhas e chaves do arquivo .env antes de iniciar.
docker compose up --build -d
```

Acesse `http://localhost:8080`. Para verificar o serviço e acompanhar os logs:

```bash
docker compose ps
docker compose logs -f
curl http://localhost:8080/health
```

No ambiente local padrão, o primeiro acesso é `admin@nexo.local` / `change-me-now`. Troque esses valores no `.env` antes de cadastrar dados reais. O PostgreSQL não é publicado na máquina host; somente a API consegue acessá-lo pela rede interna do Compose.

Para encerrar:

```bash
docker compose down
```

## Testes automatizados

```bash
docker compose build api
docker compose run --rm --no-deps \
  -e DATABASE_URL= \
  -e DATABASE_PATH=/tmp/nexo-iga-test.db \
  -e CREDENTIAL_MASTER_KEY=automated-test-master-key \
  -e JWT_SECRET=automated-test-jwt-secret-longer-than-32-bytes \
  -e ADMIN_EMAIL=admin@test.local \
  -e ADMIN_PASSWORD=automated-admin-password \
  api python -m unittest discover -s tests -v
```

A suíte usa banco temporário isolado e cobre o fluxo completo sem alterar os dados da aplicação em execução.

## Inteligência local com Qwen

O Docker Compose instala o `qwen3:1.7b` no Ollama e mantém o modelo no volume `ollama-data`. O modelo recebe somente metadados normalizados de acessos e riscos, nunca o JSON secreto da credencial. A análise generativa explica a correlação; criticidade, recomendação e tratativa permanecem protegidas pelas regras determinísticas da plataforma.

## Pré-visualizar o frontend sem Docker

Não há dependências. Abra `index.html` diretamente ou sirva a pasta:

```bash
python3 -m http.server 8080
```

Depois acesse `http://localhost:8080`. Nesse modo a API, o login e o banco não estarão disponíveis.

## Escopo implementado nesta versão

- Dashboard de postura, nota e distribuição de risco.
- Filtro por ambiente AWS, Azure e GCP.
- Gestão persistente de credenciais com validação sintática e por provedor.
- Login e perfis Administrador, Analista e Auditor.
- Gestão administrativa de usuários e bloqueio de mutações para auditores.
- Inventários de identidades e acessos.
- Áreas de inteligência de risco, acesso privilegiado, UEBA e compliance.
- Regras de Access Creep, uso real, Toxic Combination, JML, contas órfãs, postura de autenticação e Access Review.
- Auditoria filtrável e exportável em CSV.
- Layout responsivo.
- Motor de análise com inventários persistentes de identidades e concessões.
- Regras para Access Creep, uso real de permissão, Toxic Combination, JML, contas órfãs, postura de autenticação, Access Review e UEBA.

## Segurança e operação

As credenciais são validadas por provedor, criptografadas antes de serem persistidas e nunca voltam a ser exibidas: nenhum endpoint devolve o JSON secreto depois de gravado. Para editar, informe uma nova credencial ou deixe o campo em branco para manter a atual (renomear não invalida a última análise). O volume Docker `postgres-data` mantém o PostgreSQL entre reinicializações.

Os valores padrão servem apenas para desenvolvimento. Em produção, injete senhas fortes e segredos por secret manager; não altere `CREDENTIAL_MASTER_KEY` enquanto existirem credenciais gravadas. Uma implantação pública também deve usar TLS, isolamento por tenant e um cofre gerenciado (AWS Secrets Manager, Azure Key Vault ou GCP Secret Manager).

## Análise real dos ambientes

O botão **Analisar** sempre utiliza o conector do provedor. A plataforma não aceita cargas offline, dados demonstrativos ou inventários informados pelo cliente:

- AWS: STS, IAM e Organizations. Aceita access key ou assume-role com credenciais base disponíveis.
- Azure: service principal, Subscriptions e RBAC.
- GCP: service account, Resource Manager e políticas IAM dos projetos.

Os conectores solicitam operações de leitura e toleram permissões opcionais indisponíveis quando possível.

Endpoints de consulta:

- `GET /api/credentials/requirements` (campos aceitos, permissões mínimas e modelo de JSON por provedor)
- `POST /api/credentials/validate` (teste de leitura sem gravar: identidade, escopos visíveis e permissões verificadas)
- `POST /api/credentials/{id}/scan`
- `GET /api/identities`
- `GET /api/accesses`
- `GET /api/resources`
- `GET /api/findings`
- `GET /api/scans`
- `GET /api/dashboard`
- `GET /api/risk-history`
- `GET /api/privileged-access`
- `GET /api/ueba`
- `GET /api/compliance`
- `PATCH /api/findings/{id}` para resolução, aceite ou descarte auditado

Cada análise persiste a nota de postura calculada. O dashboard apresenta a evolução histórica consolidada ou filtrada por integração, permitindo comparar a postura antes e depois das remediações.

O cadastro segue o fluxo **Validar credencial → selecionar escopos → Salvar**: a validação consulta o provedor em modo leitura, lista os projetos, contas ou assinaturas visíveis e confere as permissões obrigatórias e opcionais. Somente os escopos selecionados são analisados, e a primeira análise começa automaticamente após salvar. A tela de credenciais sinaliza falhas da última análise com a mensagem do conector e credenciais que expiram em até 15 dias (validade da chave GCP, do segredo Azure via Graph ou campo `Expiration` de credenciais AWS temporárias).

Ao trocar a credencial ou os escopos, seu estado volta a pendente e os dados anteriores são invalidados. Somente uma coleta concluída altera a integração para conectada e preenche dashboard, inventários, riscos, UEBA, acesso privilegiado e compliance.
