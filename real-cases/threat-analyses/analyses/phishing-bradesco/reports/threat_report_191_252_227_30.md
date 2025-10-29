# Relatório de Threat Intelligence – IP **191.252.227.30**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io.  
> **Última coleta Shodan**: 2025‑10‑29.  

---  

## 1. Resumo Executivo
O endereço **191.252.227.30** pertence à Locaweb Serviços de Internet S/A (AS27715) e está localizado em São Paulo, BR. Embora o Shodan não retorne informações de serviços (apresenta “404: Not Found”), o URLScan.io identifica este IP como backend de múltiplos domínios recém‑criados (e com idade de 0 dias) que exibem o mesmo site de aparência legítima (blog “Veroo Cafés”), porém os nomes (ex.: *blackconviteplus.com*, *conviteblackelite.com*, *blackconviteexclusivo.com*) são típicos de campanhas de phishing ou de “convite” fraudulento. O servidor responde nas portas **80 / 443** (Apache 2.4.52 em Ubuntu) e utiliza certificado TLS válido (≈ 90 dias). Não foram encontrados CVEs associados ao host via Shodan. O conjunto de indicadores sugere possível uso do IP para hospedagem de sites de engodo ou de phishing, possivelmente como parte de botnet de hospedagem de conteúdo malicioso.

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|----------------|
| **Shodan** | Página de erro “404: Not Found” – nenhuma ficha de serviço. | O Scanning do Shodan não obteve banners; porém a ausência de dados não indica inexistência de serviços. |
| **URLScan.io** | 5 varreduras mostrando 5 domínios diferentes (ex.: `blackconviteplus.com`, `conviteblackelite.com`, `blackconviteexclusivo.com`). Todos apontam ao mesmo IP, com certificado TLS recém‑emitido (≈ 90 dias) e content‑type HTML. | Indica que o IP hospeda múltiplos domínios de curta vida – padrão de “fast‑flux” ou serviços de hospedagem de páginas de phishing/ scams. |
| **Domínios** | Todos os domínios apresentam **título** “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”. | Pode ser tentativa de camuflagem usando conteúdo aparentemente legítimo, mas a correlação com termos “convite”, “black” sugere campanha de engodo. |
| **Serviços detectados** | Servidor Apache 2.4.52 (Ubuntu) nas portas 80/443. | Servidor web padrão, mas a versão Apache 2.4.52 já tem vulnerabilidades conhecidas; embora não haja CVEs listados pelo Shodan, a presença de um software amplo pode facilitar exploração. |
| **Certificado TLS** | Emissor “R13”, validade 89‑90 dias, emitido recentemente (03‑10‑2025). | Certificado provavelmente de Let's Encrypt (R13 = “R3”?), típico de automação de certificados em ambientes de hospedagem rápida. |
| **ASN / ISP** | AS27715 – Locaweb Serviços de Internet S/A. | Provedor de hospedagem brasileiro de uso geral; a presença de atividades suspeitas pode estar relacionada a clientes mal‑intencionados ou a comprometimento de um servidor dentro da rede. |

**Conclusão comportamental:** Não há evidência direta de botnet de C2, mas o padrão de múltiplos domínios curtos, conteúdos de blog genéricos e uso de TLS recente são indicadores típicos de infraestrutura de phishing/ scam. O IP pode estar sendo usado como *phishing landing page* ou para hospedar *malvertising*.

---

## 3. Superfície de Ataque
### 3.1 Portas e Serviços
| Porta | Serviço | Comentário |
|-------|---------|------------|
| 80    | HTTP – Apache 2.4.52 (Ubuntu) | Servidor web aberto. |
| 443   | HTTPS – Apache 2.4.52 (Ubuntu) – TLS (Let's Encrypt) | Servidor web seguro. |
| (Outras) | **Nenhum** (dados do Shodan não revelam outras portas). | |

### 3.2 Vulnerabilidades (CVEs) identificadas pelo Shodan
- **Nenhuma** vulnerabilidade listada pelo Shodan no momento da coleta (2025‑10‑17).  
> *Observação:* Embora não haja CVEs explícitos, a versão Apache 2.4.52 tem vulnerabilidades conhecidas (ex.: CVE‑2024‑XXXX). Recomenda‑se verificação local.

---

## 4. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS27715** – *Locaweb Serviços de Internet S/A* |
| **Provedor (ISP)** | Locaweb Serviços de Internet S/A |
| **Localização** | **São Paulo**, **São Paulo**, **Brasil** |
| **Latitude / Longitude** | -23.5475, -46.6361 |
| **Organização registrante** | Locaweb Serviços de Internet S/A (CNPJ 02.351.877/0001‑52) |
| **Tipo de bloco** | 191.252.0.0/16 (registro LACNIC) |
| **Data de registro** | 20 dez 2013 (registro); última alteração 2022‑08‑04 |

---

## 5. Recomendações
1. **Monitoramento de Logs**  
   - Verificar logs de acesso HTTP(S) deste IP (portas 80/443) para identificar padrões de requisições suspeitas (user‑agents, referrers, volume incomum).  
   - Correlacionar com listas de domínios recém‑criados e com indicadores de phishing.

2. **Inteligência de Domínios**  
   - Consultar feeds de ameaças (e.g., PhishTank, OpenPhish, URLhaus) para validar se os domínios associados já foram catalogados como maliciosos.  
   - Realizar consultas WHOIS dos domínios para detectar abusos de registro.

3. **Análise de Conteúdo**  
   - Baixar e analisar o HTML/JS retornado (ex.: presença de scripts de redirecionamento, coleta de credenciais, download de payloads).  
   - Verificar se o site contém formulários que solicitam dados pessoais ou financeiros.

4. **Varredura de Vulnerabilidades**  
   - Executar scanners internos (Nessus, OpenVAS) focados em Apache 2.4.52 e serviços de PHP/WordPress (caso aplicável) para confirmar a ausência de vulnerabilidades conhecidas.  
   - Avaliar a configuração TLS (cipher suites, HSTS, OCSP Stapling).

5. **Comunicação com o ISP**  
   - Notificar a Locaweb através do canal de abuso (`abuse@locaweb.com.br`) com os indicadores coletados (IP, domínios, URLs) para que investiguem possível comprometimento ou uso indevido de sua infraestrutura.

6. **Bloqueio/Filtragem**  
   - Caso a organização queira mitigar risco imediato, considerar bloquear tráfego de/para este IP em firewalls ou listas de bloqueio de web‑filter, especialmente se houver detecção de tentativas de phishing contra usuários internos.

7. **Inteligência Contínua**  
   - Incorporar este IP a uma **watchlist** interna e revisar periodicamente (diariamente nas primeiras 72 h) por novos sinais de atividade maliciosa.

---  

*Este relatório tem como objetivo informar sobre potenciais riscos associados ao endereço analisado e orientar investigações adicionais. Não inclui recomendações de mitigação de vulnerabilidades específicas encontradas no serviço web.*