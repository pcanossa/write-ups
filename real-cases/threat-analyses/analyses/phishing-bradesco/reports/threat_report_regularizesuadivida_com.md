# Relatório de Threat Intelligence – Domínio **regularizesuadivida.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal (API v3).  
> **Última coleta VirusTotal**: 24/09/2025 — timestamp **1758643396** (UTC).  

---

## 1. Resumo Executivo
O domínio **regularizesuadivida.com** foi registrado em **21 de setembro de 2025** via GoDaddy (registrar ID 146) e está apontando para o endereço IP **216.238.109.50**, hospedado na infraestrutura da **Vultr (ASN AS20473 – “AS‑VULTR, US”)**. O site responde sobre **HTTPS** com um certificado **Let’s Encrypt** emitido em 21/09/2025 (validade de 89 dias).  

Os principais indicadores de risco são:

* **Tag “suspect”** atribuída pelo URLScan.io (provavelmente por ser um domínio recém‑ativado em um servidor de nuvem sem histórico reputacional).  
* **Nenhum sinal de malware** nas análises do VirusTotal (35 deteções *undetected*, 60 *harmless*, 0 *malicious*).  
* **Histórico de redirecionamento** (maio 2024) para um domínio expirado da Wix, indicando que o nome já foi usado como página de “parked” / expirado.  

Até o momento, não há evidências de que o domínio faça parte de botnets, campanhas de phishing ou C2. O conteúdo atual parece ser um blog legítimo (“Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”).

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **URLScan.io** (3 scans) | • Tag **“suspect”**.<br>• Servidor **Apache/2.4.58 (Ubuntu)**.<br>• TLS válido (Let’s Encrypt).<br>• Redirecionamento **http → https‑only**. | O rótulo “suspect” costuma ser atribuído a domínios recém‑ativados ou que ainda não possuem reputação consolidada. Não há indícios de comportamento de malware ou de comunicação de C2 no tráfego capturado (30 requisições, 2 MB de payload). |
| **VT – Análise de URL/Domínio** | • 0 % *malicious* / *suspicious*.<br>• 60 % *harmless*.<br>• Diversos motores (Kaspersky, BitDefender, etc.) relataram **“clean”**.<br>• Nenhum alerta de phishing (PhishTank, OpenPhish, Phishing Database). | Avaliação global indica que o domínio **não** está associado a conteúdo malicioso conhecido. |
| **Histórico de redirecionamento** (URLScan 2024‑05‑21) | • Redirecionamento para **www.expiredwixdomain.com** (página de “Reconnect Your Domain”). | Sugere que o domínio já esteve “parkado” ou expirado antes da atual criação; prática comum em domínios que mudam de proprietário. |
| **Whois / DNS** | • Registros **NS**: ns15.domaincontrol.com, ns16.domaincontrol.com (GoDaddy).<br>• Registro A aponta para **216.238.109.50** (Vultr).<br>• PTR → “216.238.109.50.vultrusercontent.com”. | Configuração DNS típica; uso de provedores de DNS de terceiros (GoDaddy) e hospedagem em nuvem (Vultr). |

**Conclusão de comportamento:** Não foram encontrados indicadores de uso malicioso ativo. O único ponto de atenção é a **novidade do registro** e a **ausência de reputação histórica**, que justificam a classificação “suspect” em alguns feeds, mas não há evidência concreta de comprometimento.

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20473 – AS‑VULTR, US** |
| **Provedor (ISP)** | **Vultr, Inc.** (provedor de cloud) |
| **IP** | **216.238.109.50** (PTR: 216.238.109.50.vultrusercontent.com) |
| **Localização** | **Estados Unidos – Região (não especificada), Cidade: *não divulgada* (data center Vultr).** |
| **Cidade / Região / País** | **Não disponível** (IP geolocalizado como EUA). |
| **Servidor Web** | **Apache/2.4.58 (Ubuntu)** |
| **Certificado TLS** | **Let’s Encrypt – emitido 21/09/2025, validade 89 dias** |
| **Data de criação do domínio** | **21/09/2025** (registro na GoDaddy) |
| **Idade do Apex Domain** | **≈ 1 960 dias** (≈ 5,4 anos) – indica que o nome de domínio já existia antes, porém foi **re‑registrado** recentemente. |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **IP principal** | 216.238.109.50 | Hospedado na Vultr (AS20473). |
| **Nameservers** | ns15.domaincontrol.com ; ns16.domaincontrol.com | DNS gerido pela GoDaddy. |
| **Domínio redirecionado anterior** | www.expiredwixdomain.com (IP 34.149.87.45, ASN AS396982 – Google Cloud) | Reflete uso anterior como página de “parked”. |
| **Servidor de origem de redirecionamento (maio 2024)** | 34.149.87.45 (PTR: 45.87.149.34.bc.googleusercontent.com) | Não está mais vinculado ao domínio atual. |
| **Domínios associados a mesmos nameservers** *(exemplo típico)* | Qualquer domínio sob *domaincontrol.com* (não listado aqui). | Não há evidência direta de uso malicioso compartilhado. |

> **Nota:** Uma pesquisa de “IP → domínios” em fontes públicas (Shodan, Censys, Passive DNS) pode revelar outros domínios hospedados no mesmo IP (216.238.109.50). Essa informação não foi incluída nos dados fornecidos.

---

## 5. Recomendações para Investigação Futuras
| Ação | Justificativa |
|------|----------------|
| **Monitorar feeds de reputação** (e.g., AbuseIPDB, AlienVault OTX, URLhaus) para o IP **216.238.109.50** e para o domínio. | Detectar eventuais alterações de reputação ou inclusão em listas de bloqueio. |
| **Realizar consultas Passive DNS** (e.g., PassiveTotal, SecurityTrails) para mapear outros domínios que já utilizaram o mesmo IP ou nameservers. | Verificar se o IP já foi usado por atividades suspeitas no passado. |
| **Analisar tráfego de rede** nos logs de firewall/IDS que contenham o IP ou domínio. Procure por padrões de comunicação incomuns (ex.: long‑lived outbound para múltiplos destinos). | Garantir que nenhuma máquina interna esteja estabelecendo conexão não autorizada. |
| **Verificar histórico de certificado TLS** (CT logs) para detectar mudanças frequentes ou emissões suspeitas. | Certificados rotativos podem indicar tentativa de “fast‑flux” ou abuso de certificado. |
| **Executar varredura de conteúdo web** (e.g., `wget`, `curl` com inspeção de scripts, análise de JavaScript) para identificar redirecionamentos, scripts ofuscados ou chamadas a serviços externos desconhecidos. | Confirmar que o site continua servindo apenas conteúdo legítimo. |
| **Revisar a política de renovação** do domínio e do certificado (tempo restante 89 dias). Caso o domínio não seja mais usado, considere seu bloqueio ou remoção de listas de permissão. | Evitar que o domínio seja “abandonado” e usado por terceiros para atividades maliciosas. |

---

## 6. Conclusão
Com base nas evidências coletadas:

* **Não há indícios concretos de atividade maliciosa** associada ao domínio **regularizesuadivida.com**.  
* O rótulo “suspect” do URLScan.io reflete apenas a **falta de reputação histórica**, comuns a domínios recém‑ativados em infraestruturas de nuvem.  
* O domínio está **adequadamente configurado** (HTTPS válido, certificado Let’s Encrypt, servidor Apache) e exibe **conteúdo de blog** que parece legítimo.  

Ainda assim, recomenda‑se **monitoramento contínuo** e **consulta periódica a fontes de inteligência de ameaças** para detectar rapidamente qualquer mudança de comportamento ou inclusão em listas de bloqueio.  

--- 

*Este relatório tem objetivo informativo e de apoio à decisão de segurança; não contém recomendações de mitigação de vulnerabilidades específicas do host.*  