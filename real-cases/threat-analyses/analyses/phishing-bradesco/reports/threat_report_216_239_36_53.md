# 📋 Relatório de Inteligência de Ameaças – IP **216.239.36.53**

> **Data da análise:** 27 Out 2025  
> **Fonte dos dados:** Shodan, ipinfo.io, ARIN/RIPE RDAP, URLScan.io (8 119 resultados)  

---

## 1. Resumo Executivo
- **IP:** 216.239.36.53  
- **ASN / ISP:** **AS15169 – Google LLC** (Google Frontend / Google Cloud Load Balancer)  
- **Localização:** Mountain View, Califórnia, Estados Unidos (Anycast)  
- **Portas abertas:** **80/tcp (HTTP)** e **443/tcp (HTTPS)**.  
- **Serviços observados:** Servidor Web genérico da Google (Google Frontend) que entrega requisições para *domínios* hospedados em Google Cloud Run/Google App Engine (`*.run.app`).  
- **Comportamento:** Alto volume de domínios (incluindo sites de phishing, gambling, lojas falsas) apontando CNAME para este IP. O certificado TLS exposto no Shodan é **auto‑assinado** (`CN=invalid2.invalid`), marcado com a tag *self‑signed*.  
- **Vulnerabilidades CVE:** Nenhuma vulnerabilidade diretamente associada ao IP nas bases do Shodan.  

> **Conclusão:** O IP pertence a infraestrutura pública da Google. Não há indícios de que o próprio endereço esteja comprometido, mas ele é amplamente usado como ponto de presença para serviços de terceiros – alguns deles maliciosos (phishing, jogos de azar, sites de fraude).  

---

## 2. Análise de Comportamento

| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Tipo de host** | Google Frontend (Google Cloud Load Balancer) | Servidor de borda que encaminha tráfego para instâncias de Cloud Run / App Engine. |
| **Domínios associados** | > 200 domínios nos últimos 90 dias (ex.: `insta‑dqtulhdy4a‑uc.a.run.app`, `run.app`, `test‑drive‑9‑s6uit34pua‑uc.a.run.app`, etc.) | Uso legítimo da plataforma Google, mas também como “carga útil” de sites suspeitos (phishing, gambling). |
| **Tags Shodan** | `self-signed` | O certificado TLS apresentado não é emitido por uma CA confiável – típico de ambientes de teste ou serviços que não configuraram certificados válidos. |
| **Resultados de URLScan.io** | 8 119 varreduras mostrando respostas 200/404, principalmente 404 para `run.app` (página padrão) e 200 para sub‑domínios que apontam a serviços internos da Google. | O IP responde a requisições HTTP/HTTPS, mas o conteúdo varia conforme o domínio apontado. |
| **Atividade de botnets / scanners** | Não há sinais claros de scanner de vulnerabilidades (ex.: nenhuma porta de administração, SSH, RDP). | O tráfego parece ser normalmente de navegadores ou clientes de API. |
| **Associação a C2** | Nenhum indicador de C2 (não há portas não‑HTTP, nem protocolos de comando‑e‑controle conhecidos). | Não é um servidor C2 conhecido. |
| **Abuso de hospedagem** | Muitos domínios listados são rotulados como “phishing” ou “gambling” em feeds externos e nas tags de URLScan. | A infraestrutura da Google está sendo utilizada por atores maliciosos (comum em serviços de nuvem pública). |

**Resumo:** O IP funciona como um *balancer* de tráfego da Google. Seu uso por terceiros possibilita que sites maliciosos usem a reputação do IP/GCP. Não há comprometimento direto, mas **a presença de domínios maliciosos** aponta para risco de *abuse* da infraestrutura.

---

## 3. Superfície de Ataque

### 3.1 Portas e Serviços
| Porta | Protocolo | Serviço Detectado | Comentário |
|-------|-----------|-------------------|------------|
| **80** | TCP | HTTP (Apache/NGINX “Google Frontend”) | Redireciona para o domínio solicitado via cabeçalho `Host`. |
| **443**| TCP | HTTPS (Google Frontend) | TLS apresentado: **auto‑signed**, CN `invalid2.invalid`, certificado **CA:TRUE** (pode ser usado para TLS termination sem validação). |

> Não foram encontradas portas adicionais (ex.: 22, 25, 3306) ou serviços como SMTP, FTP, SSH.

### 3.2 Vulnerabilidades (CVEs)
- **Shodan** não listou CVEs associadas ao banner ou serviço.  
- **CVEs referentes a certificados auto‑signed**: nenhum vetor de exploração direto, mas a falta de validação pode possibilitar **MITM** se o cliente aceitar o certificado sem verificação (ex.: scripts automatizados sem `curl -k`).  

> **Nota:** A vulnerabilidade mais relevante está no **uso indevido de um IP de alta reputação** para hospedar conteúdo malicioso, o que pode causar **reputação negativa** e **lista de bloqueio** para serviços que dependem da Google Cloud.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS15169 – Google LLC** |
| **ISP** | **Google LLC** |
| **Organização** | **Google LLC** |
| **País** | **Estados Unidos** |
| **Região/Estado** | **California** |
| **Cidade** | **Mountain View** |
| **Latitude / Longitude** | **38.0088, -122.1175** |
| **Anycast** | Sim (endereço Anycast usado por múltiplas bordas da Google) |
| **Blocos CIDR** | 216.239.32.0/19 (range 216.239.32.0‑216.239.63.255) |

---

## 5. Recomendações

| Área | Ação Recomendada |
|------|-------------------|
| **Monitoramento de tráfego** | - Habilitar logs de entrada/saída no firewall para 216.239.36.53. <br>- Correlacionar com conexões a domínios `*.run.app` e `*.appspot.com`. |
| **Inteligência de ameaças** | - Consultar feeds de ameaças (AlienVault OTX, AbuseIPDB, URLhaus) para domínios que apontam para este IP. <br>- Adicionar o IP a *watchlist* de SIEM para alertas de picos de requisições incomuns. |
| **Bloqueio/Filtragem** | - Se sua organização não utiliza Google Cloud Run/App Engine, considerar bloquear **todos** os fluxos de saída para este IP ou aplicar inspeção profunda (DPI) de HTTP(S). <br>- Caso use serviços GCP legítimos, aplicar **whitelisting** apenas para domínios/paths autorizados. |
| **TLS/Certificados** | - Não confiar em certificados auto‑signed retornados por este IP. Exigir validação de cadeia de confiança completa nos clientes. |
| **Abuso da infraestrutura** | - Reportar domínios de phishing/gambling à Google (via **abuse@google.com** ou AbuseIPDB) para remoção de CNAMEs abusivos. |
| **Resposta a incidentes** | - Se detectar atividade suspeita (ex.: exfiltração de dados ou comandos C2 via HTTP POST), isolar o host imediatamente e abrir ticket de *abuse* com a Google Cloud. |
| **Atualização de regras** | - Atualizar listas de bloqueio de fornecedores de segurança (e.g., Palo Alto, FortiGate) para considerar **anycast** deste bloco de IPs como potencial vetor de abuso. |

---

### Conclusão

O endereço **216.239.36.53** é um ponto de presença da Google (AS15169) que serve como *load balancer* para milhares de domínios hospedados em **Google Cloud Run / App Engine**. Embora o IP em si não apresente vulnerabilidades conhecidas, ele está sendo amplamente utilizado por terceiros, inclusive por atores maliciosos que criam sites de phishing, jogos de azar e páginas de comércio eletrônico fraudulentas.  

A principal medida de mitigação deve focar em **monitoramento e controle de tráfego** que passa por esse IP, bem como em **reportar abusos** dos domínios que o utilizam indevidamente. Dessa forma, a organização reduz o risco de ser comprometida por conteúdo malicioso hospedado na mesma infraestrutura de alta reputação da Google.