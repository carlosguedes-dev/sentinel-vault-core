# 🛡️ SENTINEL VAULT CORE // Zero-Trust Cryptographic Secret Manager

[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green?style=for-the-badge&logo=node.js)](https://nodejs.org/)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM-cyan?style=for-the-badge)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)

> **Architected for**: `carlosguedes-dev`  
> Um motor de gestão criptográfica de segredos, cofre zero-trust e telemetria de produção com interface visual Cyberpunk HUD.  
> Desenvolvido para resolver de forma definitiva as vulnerabilidades e anti-patterns identificados na auditoria de segurança dos repositórios anteriores.

---

## 💎 O que é o Sentinel Vault Core?

O **Sentinel Vault Core** é uma API RESTful de nível de produção com arquitetura limpa em camadas (Clean/Hexagonal Architecture), construída para armazenar, criptografar e auditar segredos de ambiente (chaves de API, credenciais de banco, tokens de pagamento) com **cifragem autenticada AEAD (AES-256-GCM)** e derivação de chaves via **scrypt**.

Acompanha um **Dashboard Telemetria HUD** em tempo real com estética Cyberpunk/Glassmorphism, feedback dinâmico de entropia e renderização DOM 100% segura contra Cross-Site Scripting (XSS).

---

## 🛡️ Melhorias de Segurança Implementadas (Aprendizado da Auditoria)

| Falha Identificada nos Projetos Anteriores | Como o Sentinel Vault Core Resolve |
| :--- | :--- |
| **Fallback inseguro de segredo JWT** (`process.env.JWT_SECRET \|\| "default"`) | **Fail-Fast Boot**: Validação rigorosa via Zod no arquivo `env.ts`. Se a chave for omitida, for menor que 32 caracteres ou contiver padrões de placeholder, a aplicação se recusa a iniciar. |
| **Credenciais de banco em texto plano em `.env` e Git** | `.gitignore` de nível militar excluindo qualquer `.env*`, `*.db`, `node_modules` e `.bak`. Fornece `.env.example` estritamente documentado. |
| **Senhas mestras e backdoors hardcoded** (`devguedes02`, `espirita2026`) | **Zero senhas fixas**: Autenticação baseada em PBKDF2/scrypt com salt individual de 16 bytes e comparação em tempo constante (`crypto.timingSafeEqual`) contra ataques de temporização. |
| **Tokens e IDs gerados via `Math.random()`** | Substituição integral por **CSPRNG** de nível de sistema operacional (`crypto.randomUUID()` e `crypto.randomBytes()`). |
| **CORS aberto (`*`) e ausência de Rate Limiting** | CORS restrito com **whitelist de origens explícitas** e **Rate Limiter de janela deslizante** (sliding-window) para bloquear ataques de força bruta no login. |
| **DOM XSS via `innerHTML` em templates estáticos** | Renderização declarativa e segura no cliente utilizando `document.createElement`, `textContent` e atributos seguros. Zero `innerHTML`. |
| **Headers e CSP fracos (permitindo `unsafe-eval`)** | Helmet configurado com **Content Security Policy estrita** sem `'unsafe-eval'`, HSTS ativado e `X-Content-Type-Options: nosniff`. |

---

## 🏛️ Arquitetura do Projeto

```
sentinel-vault-core/
├── src/
│   ├── config/
│   │   └── env.ts                  # Validação fail-fast de ambiente via Zod
│   ├── core/
│   │   ├── crypto/
│   │   │   ├── cipher.ts           # Cifragem autenticada AES-256-GCM + IV + AuthTag
│   │   │   ├── hasher.ts           # Hashing com scrypt + salt dinâmico + timingSafeEqual
│   │   │   └── tokens.ts           # Gerador CSPRNG de IDs e chaves seguras (sem Math.random)
│   │   └── errors/
│   │       └── app-error.ts        # Hierarquia de erros com status HTTP
│   ├── domain/
│   │   ├── models/                 # Modelos de domínio (SecretItem, User, RBAC)
│   │   └── repositories/           # Contratos de repositório
│   ├── infrastructure/
│   │   ├── database/               # Repositório de cofre em memória isolado
│   │   └── middleware/             # Rate Limiter, Helmet, CORS e Autenticação
│   ├── presentation/
│   │   ├── controllers/            # Controladores de Auth, Vault e Health
│   │   ├── routes/                 # Roteamento modular da API (/api/v1)
│   │   └── views/public/           # Dashboard HUD Telemetria (HTML/CSS/JS seguros)
│   ├── server.ts                   # Montagem do app Express
│   └── index.ts                    # Entrypoint com graceful shutdown
└── tests/                          # Suíte de testes automatizados de segurança
```

---

## 🚀 Como Rodar o Projeto

### 1. Instalar as Dependências
Abra o terminal na pasta do projeto e instale as dependências:
```bash
cd sentinel-vault-core
npm install
```

### 2. Rodar a Suíte de Testes Automatizados
Valide a integridade criptográfica e os mecanismos de defesa:
```bash
npm test
```

### 3. Iniciar o Servidor em Modo de Desenvolvimento
```bash
npm run dev
```

Acesse o painel no navegador:  
👉 **http://localhost:4000**

---

## 🔐 Credenciais Padrão de Inicialização (Local Dev)
No primeiro boot em ambiente local, o sistema cria automaticamente o usuário administrativo:
* **Usuário**: `sentinel.admin`
* **Senha Inicial**: `SentinelAdmin#2026`
* **Painel da API**: `http://localhost:4000/api/v1/health`

---

## 📡 Endpoints da API

| Método | Endpoint | Proteção | Descrição |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Pública | Telemetria do sistema, memória, uptime e status dos motores criptográficos. |
| `POST` | `/api/v1/auth/login` | Rate Limited | Autenticação com credenciais e emissão de token de sessão assinado. |
| `POST` | `/api/v1/auth/generate-api-key` | ADMIN | Gera nova API Key de produção com 192 bits de entropia (`sk_live_...`). |
| `GET` | `/api/v1/vault/secrets` | Autenticada | Lista metadados de todos os segredos arquivados (sem vazar valores). |
| `POST` | `/api/v1/vault/secrets` | OPERATOR / ADMIN | Criptografa com AES-256-GCM e armazena novo segredo no cofre. |
| `GET` | `/api/v1/vault/secrets/:id/decrypt` | OPERATOR / ADMIN | Decifra o segredo com verificação do AuthTag e registra acesso no log. |
| `DELETE`| `/api/v1/vault/secrets/:id` | ADMIN | Expurga definitivamente o segredo do cofre. |
