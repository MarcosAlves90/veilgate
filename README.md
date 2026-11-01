# VeilGate

**Proxy local de privacidade para clientes compatíveis com OpenAI Chat Completions, com foco em Hermes Agent e FreeLLMAPI.**

O VeilGate examina requisições de texto **antes** de chegarem ao FreeLLMAPI. Ele mascara identificadores comuns e **rejeita requisições** que aparentemente contêm segredos. Nenhum dado de prompt é registrado, armazenado, enviado para telemetria ou processado por serviços de terceiros pelo próprio VeilGate.

> **Aviso:** filtragem baseada em padrões **não garante anonimização**. Informações contextuais, nomes próprios, endereços e formatos desconhecidos podem escapar. Provedores externos continuam recebendo sua identidade de conta e metadados de conexão via FreeLLMAPI. Leia [Modelo de ameaças](docs/threat-model.md).

## Arquitetura

```text
Hermes Agent / cliente OpenAI
         |
         v
VeilGate  http://127.0.0.1:8080/v1
  ├── máscara local de e-mail, CPF/CNPJ válidos, celular BR, usuário em /Users ou /home
  ├── termos personalizados em arquivo local ignorado pelo Git
  ├── bloqueio de credenciais (padrões conhecidos)
  ├── limita JSON, tamanho e rotas; bloqueia multimodal
  └── repassa JSON / SSE sem alterar a resposta
         |
         v
FreeLLMAPI http://127.0.0.1:3001/v1
         |
         v
Provedores externos
```

## Requisitos

Python **3.11+**. Sem dependências de runtime (biblioteca padrão). Compatível com macOS Apple Silicon, Linux e Windows.

## Instalação

Clone o repositório e instale o pacote:

```bash
git clone https://github.com/MarcosAlves90/veilgate.git
cd veilgate
python3 -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
```

Para repositórios privados, o clone exige autorização de acesso no GitHub.

Execute o FreeLLMAPI na porta `3001` como usual. Em outro terminal, inicie:

```bash
veilgate --upstream http://127.0.0.1:3001 --listen 127.0.0.1 --port 8080
```

Confira:

```bash
curl http://127.0.0.1:8080/healthz
```

O endereço para o Hermes Agent (ou outro cliente OpenAI) passa a ser:

```text
base_url: http://127.0.0.1:8080/v1
```

**Não altere** sua chave unificada `freellmapi-...`: ela continuará sendo repassada exclusivamente ao FreeLLMAPI local no cabeçalho `Authorization`. Preserve as demais configurações de modelo e modo API de seu cliente. Use Chat Completions (`/v1/chat/completions`).

## Teste com dados fictícios

A variável abaixo é apenas exemplo; substitua por sua chave *local* do FreeLLMAPI:

```bash
export FREELLMAPI_API_KEY='freellmapi-CHAVE_DE_TESTE'
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $FREELLMAPI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"auto","messages":[{"role":"user","content":"Contato: ficticio@example.com; diga olá"}]}'
```

A resposta **não é restaurada automaticamente**: se o modelo mencionar um pseudônimo como `[REDACTED_EMAIL_1]`, ele permanecerá visível. O VeilGate mantém SSE streaming (`"stream":true`) sem modificação da resposta, inclusive deltas de tool calls.

## Termos privados próprios

```bash
cp private-terms.example.txt private-terms.txt
# Edite private-terms.txt com dados locais, nunca faça commit dele
veilgate --private-terms private-terms.txt
```

Cada linha não comentada (mínimo três caracteres) será mascarada sem considerar caixa. Evite termos genéricos que afetariam código. Não configure nomes muito curtos. Arquivos ausentes causam falha na inicialização.

## Configuração

| Argumento | Variável | Padrão |
| --- | --- | --- |
| `--listen` | `VEILGATE_LISTEN` | `127.0.0.1` |
| `--port` | `VEILGATE_PORT` | `8080` |
| `--upstream` | `VEILGATE_UPSTREAM` | `http://127.0.0.1:3001` |
| `--private-terms` | `VEILGATE_PRIVATE_TERMS_FILE` | nenhum |

O proxy recusa upstreams remotos, conexões que não sejam loopback e redirecionamentos HTTP. A única rota POST suportada é `/v1/chat/completions`. `GET /v1/models` e `GET /healthz` também estão disponíveis. Requisições inválidas ou incompatíveis recebem erro **sem serem encaminhadas**.

## Testes

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Os testes usam um upstream HTTP simulado, não fazem chamadas a modelos reais e verificam o corpo efetivamente recebido pelo upstream. O CI repete os testes em Python 3.11, 3.12 e 3.13.

Para rodar os mesmos testes e gerar um relatório de cobertura Cobertura XML:

```bash
python -m pip install -e '.[dev]'
python scripts/validate.py test
python scripts/validate.py coverage
```

O arquivo `coverage.xml` é gerado localmente e ignorado pelo Git. A política de validação do [POLIS](https://github.com/MarcosAlves90/polis) está em `.polis/policy.json`; com o CLI instalado, use `polis plan --repo .` e `polis gates --repo .`. POLIS não é uma dependência de execução do proxy.

## Limitações

- Não protege prompts enviados fora do proxy nem dados já fornecidos a serviços externos.
- Não reconhece confiavelmente nomes, endereços físicos, dados sem padrão, segredos desconhecidos ou texto confidencial por inferência.
- Não inspeciona cabeçalhos além do necessário: `Authorization` é encaminhado ao gateway local e não enviado pelo VeilGate diretamente aos provedores.
- Não aceita imagens, áudio, arquivos, Responses API, completions legadas ou outros formatos não documentados. Isso é intencional para impedir bypass silencioso.
- Tokens de API presentes no corpo são bloqueados por heurística, não por cobertura exaustiva.
- Pseudônimos são consistentes **dentro de uma requisição**; não há armazenamento ou associação entre sessões.
- Para confidencialidade forte, prefira execução totalmente local do modelo e não use serviços externos.

## Comunidade e segurança

Consulte [CONTRIBUTING.md](CONTRIBUTING.md) para contribuições, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) para normas de participação e [SECURITY.md](SECURITY.md) antes de relatar uma vulnerabilidade. Use apenas dados fictícios nos relatos e testes.

## Licença

[MIT](LICENSE). Contribuições e relatórios de bugs sem dados pessoais são bem-vindos.
