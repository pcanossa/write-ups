# Relatório de Threat Intelligence – Domínio **rendaverificada.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 2025‑10‑02 (timestamp 1759363798).  

---

## 1. Resumo Executivo
O domínio **rendaverificada.com** foi registrado em **24/09/2025** (idade de 1 dia) no registrador **GoDaddy**, apontando para o endereço IP **216.238.109.50**, que pertence ao provedor de cloud **Vultr** (ASN AS20473 – *AS‑VULTR, US*). O site está hospedado em um servidor **Apache/2.4.58 (Ubuntu)**, utiliza certificado **Let’s Encrypt** válido até **23/12/2025** e exibe a página “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”.  

Nenhum mecanismo de detecção (33 antivírus/antimalware) registrou comportamento **malicioso** ou **suspicious** no domínio; todos os resultados do VirusTotal são **harmless** ou **undetected**. Os feeds de inteligência (URLHaus, PhishTank, etc.) também não listam o domínio ou o IP como malicioso.  

Em resumo, o domínio apresenta características típicas de um site recém‑criado, hospedado em infraestrutura de cloud pública, sem indicadores claros de uso malicioso até o momento.

---

## 2. Análise de Comportamento
| Fonte | Indicador | Evidência |
|-------|-----------|-----------|
| **URLScan.io** (2 varreduras) | **Idade do domínio** – 1 dia | `apexDomainAgeDays: 1` |
| | **Servidor Web** – Apache/Ubuntu | `server: "Apache/2.4.58 (Ubuntu)"` |
| | **TLS** – Let’s Encrypt, validade 89 dias | `tlsValidDays: 89`, `tlsIssuer: "E8"` |
| | **Conteúdo** – Blog de café (texto em PT‑BR) | `title: "Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés"` |
| | **Redirecionamento** – HTTP → HTTPS (force‑only) | `redirected: "https-only"` |
| **VirusTotal** | **Detecção** – 0 malicious, 0 suspicious | `last_analysis_stats: {"malicious":0,"suspicious":0}` |
| | **Engines** – Todas classificam como **harmless/undetected** | Lista extensa de engines (Acronis, Kaspersky, BitDefender, etc.) |
| **Whois / RDAP** | **Registrante** – Dados ofuscados (strings aleatórias) | `Registrant city: a7319ae5e6c95df5`, `Registrant email: 4178368b5e3a4932s@` |
| | **Status** – “client delete/renew/transfer prohibited” (tipicamente usado por registradores para impedir alterações automáticas) | `status: ["client delete prohibited", ...]` |
| **DNS** | **A record** – IP único 216.238.109.50 | `type: "A", value: "216.238.109.50"` |
| | **NS** – ns75/ns76.domaincontrol.com (GoDaddy) | `value: "ns75.domaincontrol.com"` / `ns76.domaincontrol.com` |
| | **PTR** – 216.238.109.50.vultrusercontent.com | `ptr: "216.238.109.50.vultrusercontent.com"` |

**Conclusão comportamental**  
- Não há indícios de participação em botnets, servidores C2, phishing ou distribuição de malware.  
- O domínio está **novo**, possivelmente criado para um blog ou site institucional.  
- O uso de um provedor de cloud (Vultr) e de certificado Let’s Encrypt é padrão para sites recém‑lançados.  
- O registrante apresenta informações de contato ofuscadas, prática comum em registros de baixo custo ou sites de teste, mas não indica necessariamente atividade maliciosa.

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20473 – AS‑VULTR, US** |
| **Provedor (ISP)** | **Vultr, Inc.** (provedor de cloud / IaaS) |
| **IP** | **216.238.109.50** |
| **Localização do IP** | **Estados Unidos** – provável data center na região **East Coast (por exemplo, NJ / NY)** (geolocalização baseada em bases públicas de IP). |
| **Cidade / Região** | Não disponível (IP de datacenter). |
| **País** | **United States (US)** |
| **Serviço DNS** | **GoDaddy DNS** (ns75/ns76.domaincontrol.com). |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio principal** | `rendaverificada.com` | Apex domain analisado. |
| **IP associado** | `216.238.109.50` | Único A record. |
| **Nameservers** | `ns75.domaincontrol.com`, `ns76.domaincontrol.com` | Servidores de DNS da GoDaddy. |
| **PTR** | `216.238.109.50.vultrusercontent.com` | Indica hospedagem na Vultr. |
| **Outros domínios observados** | Nenhum adicional encontrado nas duas varreduras do URLScan.io. |
| **Subdomínios** | Não listados nos registros DNS públicos. |
| **Certificado** | `rendaverificada.com` – Let’s Encrypt (E8) – validade 24/09/2025 → 23/12/2025. |

---

## 5. Recomendações (próximos passos de investigação)

1. **Monitoramento contínuo**  
   - Incluir o domínio e o IP **216.238.109.50** em listas de observação nos SIEM/EDR.  
   - Verificar diariamente se alguma engine de reputação (VirusTotal, URLHaus, AbuseIPDB) passa a marcar o domínio/IP como malicioso.

2. **Análise de tráfego**  
   - Correlacionar logs de firewall ou proxy corporativo para identificar tentativas de acesso ao domínio/IP.  
   - Caso haja tráfego interno, analisar padrões (frequência, horário, origem interna) para descartar exfiltração ou beaconing.

3. **Avaliação de conteúdo**  
   - Realizar um **crawl** do site (por exemplo, usando `wget` ou `scrapy`) para capturar scripts, recursos externos e possíveis **payloads** que não foram carregados na primeira varredura.  
   - Verificar por **links para download** de arquivos executáveis ou documentos suspeitos.

4. **Verificação de certificados**  
   - Monitorar a renovação do certificado Let’s Encrypt; mudanças súbitas no emissor ou nos SANs podem indicar comprometimento.

5. **Inteligência de terceiros**  
   - Consultar bases de dados de **threat intel** (e.g., Spamhaus, IBM X-Force, OTX) para validar se o IP ou domínio foram recentemente adicionados a listas de má reputação.  
   - Pesquisar por “rendaverificada.com” em fóruns de segurança e em redes sociais para detectar relatos de golpes ou phishing.

6. **Análise de WHOIS**  
   - Apesar das informações de contato estarem ofuscadas, o registrante pode estar usando um serviço de privacidade. Caso haja necessidade de contato legal, preparar pedido de informação ao registrar (GoDaddy) por meio de processo judicial ou notificação de abuso.

7. **Teste de vulnerabilidades**  
   - Se for necessário avaliar a superfície de ataque, executar um **scan de vulnerabilidades web** (ex.: OWASP ZAP, Nikto) com permissão, focando em versões do Apache/Ubuntu e possíveis plugins de CMS (WordPress, Joomla etc.) caso detectados.

---

## 6. Conclusão
Com base nas evidências atuais, **rendaverificada.com** não demonstra comportamentos maliciosos conhecidos. O domínio é **recém‑registrado**, hospedado em infraestrutura de cloud pública (Vultr) e apresenta um certificado TLS válido. Não há bloqueios ou listagens em feeds de ameaças. Contudo, a natureza recente e a ausência de informações de contato claras recomendam **monitoramento ativo** para detectar rapidamente qualquer mudança de perfil (ex.: inclusão em listas de phishing, alterações de conteúdo, comunicação com C2).  

---