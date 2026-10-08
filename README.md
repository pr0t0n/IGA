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

Interface única no design system **Modernist** (Archivo, grade modular, réguas de 2px, acento vermelho), com menu lateral e as telas:

- **Visão geral** — nota de risco consolidada (0 = sem exposição, 100 = máxima), distribuição por severidade, risco por provedor (clique para filtrar), KPIs com variação no período, tendência de 7/30/90 dias, achados por regra, mapa de calor módulo × provedor, ambientes de maior risco, riscos prioritários, anomalias UEBA e atendimento por framework.
- **Identidades** — KPIs (humanas, serviço, órfãs, sem MFA, inativas > 90 dias), filtros, nota de risco por identidade, painel lateral com sinais de risco e solicitação de revisão ao responsável; exportação CSV.
- **Inventário de acessos** — concessões com origem (direta/grupo), último uso quando o provedor informa, curingas, visões por projeto (com drill-down projeto → papel → conta), por papel e por conta.
- **Inteligência e riscos** — abas por regra com descrição e critério, filtro por severidade, ações **Remediar**, **Aceitar** (com justificativa obrigatória) e **Reabrir**; o tratamento é preservado nas análises seguintes; leitura local do Qwen.
- **Acesso privilegiado** — permanentes × JIT, papéis de alto impacto, MFA, uso, nota de exposição, **Converter para JIT** (solicitação registrada e auditada) e dossiê com análise local.
- **UEBA** — eventos por hora (24 h) a partir dos logs coletados, categorias (escalada de privilégio, criação de credencial, acesso negado, horário atípico), esperado × observado, **Abrir incidente** e **Marcar como comportamento esperado**; diagnóstico de cobertura de telemetria.
- **Credenciais** — validação antes de salvar, seleção de escopos, análise automática, falha e validade da credencial.
- **Auditoria** — trilha da plataforma encadeada por hash SHA-256 unificada aos logs dos provedores, filtros por origem e resultado, detalhe em JSON e exportação de evidências.
- **Compliance** — ISO 27001, SOX ITGC, LGPD e CIS com status e evidência calculados das regras; **campanhas de Access Review** com decisões Manter/Revogar que recertificam a concessão; relatório CSV.
- **Administração** — parâmetros das regras (aplicados na próxima análise), agendamento (manual, diário, 6 h, horário), notificações por webhook Slack/Teams (risco crítico novo, UEBA, credencial, resumo semanal) e usuários com convite por senha temporária.

Perfis: **Administrador**, **Analista**, **Auditor** (somente leitura) e **Leitor** (somente leitura, sem trilha de auditoria).

### Agendamento e notificações

O agendador roda dentro da API e verifica a cada minuto as credenciais vencidas conforme a frequência escolhida em Administração (padrão: manual). Defina `SCHEDULER_ENABLED=0` para desativá-lo. O webhook precisa ser `https://` e recebe `{"text": "..."}`, formato aceito por Slack e Microsoft Teams.

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
- `GET /api/dashboard/overview?period=7|30|90&credential_id=&provider=`
- `GET /api/identities/summary`, `GET /api/accesses/summary`, `GET /api/privileged-access/summary`
- `POST /api/privileged-access/{id}/jit`
- `GET /api/ueba/overview`
- `GET /api/audit/trail`
- `GET /api/compliance/frameworks`
- `GET|POST /api/reviews`, `GET /api/reviews/{id}`, `PATCH /api/reviews/{id}/items/{item}`
- `GET|PUT /api/settings`
- `POST /api/users/invite`
- `GET /api/dashboard`
- `GET /api/risk-history`
- `GET /api/privileged-access`
- `GET /api/ueba`
- `GET /api/compliance`
- `PATCH /api/findings/{id}` para remediação, aceite (com justificativa), incidente, resolução ou reabertura auditados

Cada análise persiste a nota de postura calculada. O dashboard apresenta a evolução histórica consolidada ou filtrada por integração, permitindo comparar a postura antes e depois das remediações.

O cadastro segue o fluxo **Validar credencial → selecionar escopos → Salvar**: a validação consulta o provedor em modo leitura, lista os projetos, contas ou assinaturas visíveis e confere as permissões obrigatórias e opcionais. Somente os escopos selecionados são analisados, e a primeira análise começa automaticamente após salvar. A tela de credenciais sinaliza falhas da última análise com a mensagem do conector e credenciais que expiram em até 15 dias (validade da chave GCP, do segredo Azure via Graph ou campo `Expiration` de credenciais AWS temporárias).

Ao trocar a credencial ou os escopos, seu estado volta a pendente e os dados anteriores são invalidados. Somente uma coleta concluída altera a integração para conectada e preenche dashboard, inventários, riscos, UEBA, acesso privilegiado e compliance.
