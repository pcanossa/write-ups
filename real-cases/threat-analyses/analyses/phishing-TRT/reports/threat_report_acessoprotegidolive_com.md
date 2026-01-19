# Relatório de Threat Intelligence – Domínio **acessoprotegidolive.com**

> **Fonte dos dados**: WHOIS (whois.tucows.com), VirusTotal (API v3), URLScan.io, AlienVault OTX, consulta DNS pública, cURL, Certificados SSL/TLS (crt.sh).  
> **Timestamp da Análise**: 2026-01-14T12:54:54.783520.  

---  

## 1. Resumo Executivo
O domínio **acessoprotegidolive.com** foi registrado em 27‑Nov‑2025 via **Tucows Domains Inc.** e utiliza servidores de nomes da **Cloudflare** (alec.ns.cloudflare.com / bonnie.ns.cloudflare.com). Não há evidência de um proprietário público – os dados de contato estão ofuscados e apontam para a jurisdição de **Saint Kitts and Nevis** (CN: Charlestown).  

O domínio resolve para **IP 104.26.9.96** (e variantes 104.26.8.96 / 172.67.75.34), blocos de IP pertencentes à rede **Cloudflare** (ASN 13335). Os registros DNS não apresentam DNSSEC.  

No **VirusTotal**, a maioria dos scanners classifica o domínio como “undetected” (93/93), porém há **1 voto “malicious”** e o domínio aparece marcado como “newly registered website” pelo **Forcepoint ThreatSeeker**. Não foram encontradas amostras de arquivos ou URLs associadas que estejam listadas como maliciosas.  

Os sub‑domínios analisados via **URLScan.io** (`verificacentral.acessoprotegidolive.com`, `entrardadosprocess.acessoprotegidolive.com`, `acess200.acessoportalatendimento.app`) são servidos pelos mesmos IPs de Cloudflare e apresentam tráfego HTTP/HTTPS com múltiplas requisições (até 9 requests por análise). Não há indicadores de comprometimento direto, porém o padrão de uso (sub‑domínios que redirecionam ou hospedam “forms” de coleta de dados) é típico de **infraestrutura de apoio a campanhas de phishing ou coleta de credenciais**.  

**Conclusão geral:** domínio recém‑registrado, hospedado em CDN pública, não marcado como malicioso pelos scanners, porém **associado a tráfego suspeito e a sub‑domínios potencialmente usados para coleta de informações**. Recomenda‑se tratá‑lo como risco **médio‑alto** até que evidências adicionais sejam obtidas.

---  

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|------|-----------|---------------|
| **WHOIS** | Registro recentíssimo (27‑Nov‑2025), privacy‑protected, registrante em Saint Kitts and Nevis | Domínio possivelmente criado para uso temporário ou ocultar identidade – prática comum em campanhas de phishing e C2. |
| **DNS** | Nameservers Cloudflare, sem DNSSEC, IPs 104.26.9.96 / 104.26.8.96 (AS 13335 – Cloudflare) | Utiliza CDN pública para anonimizar a origem real; dificulta rastreamento de servidor de origem. |
| **URLScan.io** (várias execuções) | Sub‑domínios (`verificacentral`, `entrardadosprocess`, `acess200`) apontam para mesmos IPs; conteúdo carregado via HTTPS; tráfego “uniqIPs” = 4, “uniqCountries” = 1 (único país: EUA) | Indica **infraestrutura centralizada** para disponibilizar diferentes “portais” – padrão de **phishing kits** que criam múltiplas páginas de coleta. |
| **VirusTotal** | 93/93 scanners “undetected”; total_votes malicious = 1; categoria “newly registered website” | Ainda não detectado como malware, mas a presença de voto maligno sugere que ao menos um analista ou feed considerou o domínio suspeito. |
| **AlienVault OTX** | Nenhum pulso associado | Falta de notoriedade em feeds OTX, possivelmente por ser muito recente. |
| **cURL** | Falha de resolução DNS (Could not resolve host) → provavelmente bloqueio ou ausência de registro A‑record direto (apenas CNAME para Cloudflare). | DNS configurado para servir apenas via Cloudflare; ausência de registro público pode ser estratégia anti‑recon. |
| **Certificado SSL/TLS** | Emissão recente (27‑Nov‑2025) por **Google Trust Services** (base Let’s Encrypt e Google Trust Services); cobre `*.acessoprotegidolive.com` | Certificado válido e confiável, reforça a aparência de legitimidade – comum em campanhas de phishing que dependem de HTTPS para evitar alertas de navegadores. |

### Táticas/Procedimentos (ATT&CK) observados
| Tática | Técnica | Evidência |
|--------|----------|------------|
| **Reconhecimento de Rede** | T1018 – “Remote System Discovery” | Sub‑domínios apontam para IPs Cloudflare que podem ser usados para mapear a infraestrutura. |
| **Hóspede Web Malicioso** | T1059 – “Command and Control (Web)” | Uso de HTTPS via Cloudflare para esconder C2 ou entrega de payloads. |
| **Phishing** | T1566.002 – “Phishing: Spearphishing Link” | Sub‑domínios provavelmente hospedam formulários de captura de credenciais. |
| **Uso de Certificado Legítimo** | T1606 – “Forge Web Credentials” | Certificado de autoridade confiável (Google Trust Services) para gerar confiança. |
| **Obfuscação** | T1027 – “Obfuscated Files or Information” | Não há arquivos analisados, mas a prática de criar sub‑domínios “aleatórios” indica tentativa de tornar a detecção mais difícil. |

---  

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | 13335 – Cloudflare, Inc. |
| **ISP / Provedor** | Cloudflare (serviço de CDN/DDoS protection) |
| **Região / País** | Principalmente **Estados Unidos** (os IPs 104.26.x.x são alocados nos EUA). |
| **Cidade** | Não determinado (IP de Cloudflare não expõe localização exata). |
| **Endereço IPv4 (resolvido)** | 104.26.9.96, 104.26.8.96, 172.67.75.34 (todos pertencentes ao bloco Cloudflare). |
| **IPv6** | Não há registro AAAA. |
| **DNSSEC** | **Não** (unsigned). |
| **Data de criação** | 27‑Nov‑2025 (registro WHOIS). |
| **Data de expiração** | 27‑Nov‑2026. |

---  

## 4. Domínios e IPs Relacionados
### Sub‑domínios observados (URLScan.io)  
| Sub‑domínio | IP resolvido | Observação |
|-------------|---------------|------------|
| `verificacentral.acessoprotegidolive.com` | 104.26.9.96 | Página genérica (possível “landing page”). |
| `entrardadosprocess.acessoprotegidolive.com` | 104.26.8.96 / 172.67.75.34 | Nome sugestivo de coleta de dados. |
| `acess200.acessoportalatendimento.app` (sub‑domínio de outro domínio) | 104.26.8.96 | Redireciona para `verificacentral.acessoprotegidolive.com`. |
| `acess200.acessoportalatendimento.app` (várias variações) | 104.26.8.96 / 104.26.9.96 | Repetidas execuções de sandbox (tag “falconsandbox”). |

### Endereços IP principais
| IP | ASN / ISP | Observação |
|----|-----------|------------|
| 104.26.9.96 | AS13335 – Cloudflare | Servidor de front‑end para sub‑domínios acima. |
| 104.26.8.96 | AS13335 – Cloudflare | Mesmo bloco, possível balanceamento. |
| 172.67.75.34 | AS13335 – Cloudflare | Entrada adicional, possivelmente usada como fallback. |

### Domínios “parentais” e “sister” (identificados nos metadados de URLScan)  
- `acessoportalatendimento.app` (aponta para sub‑domínio `acess200`).  
- `acessoprotegidolive.com` (domínio principal).  

> Não foram encontrados outros domínios listados em pulsos OTX ou feeds de ameaças populares.

---  

## 5. Recomendações de Investigação
1. **Monitoramento DNS**  
   - Capture consultas ao domínio `acessoprotegidolive.com` e a todos os sub‑domínios listados nos logs do DNS resolver interno (ou firewall DNS).  
   - Alertas para resoluções a IPs da Cloudflare fora do escopo corporativo ou com frequência incomum.  

2. **Análise de tráfego HTTP(S)**  
   - Inspecione logs de proxy/web gateway em busca de requisições GET/POST para `*.acessoprotegidolive.com`.  
   - Procure por parâmetros que indiquem submissão de dados (ex.: `email=`, `senha=`, `cpf=`).  

3. **Bloqueio de indicadores**  
   - Inclua os IPs 104.26.9.96, 104.26.8.96 e 172.67.75.34 em listas de bloqueio de saída (firewall), a menos que sejam usados por serviços legítimos da organização.  
   - Adicione o domínio principal e sub‑domínios a políticas de bloqueio de URL (Web‑Proxy, Secure Web Gateway).  

4. **Threat Hunting**  
   - Correlacione hashes de arquivos ou scripts que possam estar referenciados nos sub‑domínios (ex.: arquivos JS carregados) com a base de dados de endpoints.  
   - Verifique se houveram alertas de credenciais vazadas que incluam URLs com esse domínio.  

5. **Inteligência adicional**  
   - Consulte feeds de reputação de IPs da Cloudflare (e.g., AbuseIPDB, IPQualityScore) para validar se os mesmos IPs foram reportados por outras campanhas.  
   - Use ferramentas de Passive DNS para identificar histórico de resolução deste domínio (possíveis usos anteriores).  

6. **Verificação de e‑mail**  
   - Atualize regras de filtragem de e‑mail para detectar mensagens contendo links ou imagens que apontem para `acessoprotegidolive.com` ou seus sub‑domínios.  

7. **Snapshot de certificado**  
   - Registre o certificado atual (emissões Let’s Encrypt / Google Trust Services) para futuro comparativo, caso o domínio passe por renovação e/ou troca de CA.  

---  

## 6. Conclusão
Embora **acessoprotegidolive.com** ainda não tenha sido rotulado como “malicioso” pelos principais motores de antivírus, seu **perfil de registro recente, uso de Cloudflare como CDN pública, sub‑domínios com nomes que sugerem coleta de dados e um voto “malicious” no VirusTotal** sugerem que pode estar sendo usado como **infraestrutura de apoio a campanhas de phishing ou coleta de credenciais**. A ausência de DNSSEC e o uso de certificados SSL/TLS legítimos reforçam a tentativa de gerar confiança ao usuário final.  

Recomenda‑se **monitoramento ativo, bloqueio seletivo e investigação de tráfego associado**, especialmente em ambientes onde a entrada de credenciais sensíveis é comum. Até que haja evidência de comprometimento direto ou sinalizações adicionais de feeds de risco, o domínio deve ser considerado **potencial risco médio‑alto** e tratado como tal nas políticas de segurança da organização.  