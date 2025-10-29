# Relatório de Threat Intelligence – IP **161.35.50.50**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io (sem resultados).  
> **Última coleta Shodan**: 2025‑10‑17.  

---

## 1. Resumo Executivo
O endereço **161.35.50.50** pertence à DigitalOcean (ASN **AS14061**) e está localizado em **North Bergen, New Jersey, EUA**. O host resolve para **convitecenturion.com**, um site de blog que utiliza **Apache httpd 2.4.58** (Ubuntu) nas portas **80 (HTTP)** e **443 (HTTPS)**, além de **OpenSSH 9.6p1** na porta **22 (SSH)**. O serviço web apresenta mais de **30 CVEs** associados à versão do Apache, incluindo vulnerabilidades críticas (CVSS ≥ 9). Não há indicadores claros de que o IP faça parte de botnets ou de atividades de scanner; entretanto, a presença de um servidor exposto com várias vulnerabilidades pode torná‑lo um alvo atraente para exploração ou para uso como ponto de pivotagem.  

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **Shodan – Tags** | `cloud` | Indica que o host está em infraestrutura de nuvem (DigitalOcean). |
| **Shodan – Última vez visto** | 2025‑10‑27 | O host está ativo recentemente. |
| **Portas abertas** | 22, 80, 443 | Serviços SSH e Web (HTTP/HTTPS) expostos ao público. |
| **Banner SSH** | OpenSSH 9.6p1 (Ubuntu) | Versão atual, sem vulnerabilidades conhecidas críticas. |
| **Banner HTTP** | Apache 2.4.58 (Ubuntu) | Versão antiga, com várias CVEs (lista abaixo). |
| **Domínio / Hostname** | convitecenturion.com – blog de cafés | Uso aparente como site institucional/pessoal, sem indício direto de atividade maliciosa. |
| **URLScan.io** | Nenhum resultado | Não há evidência de interações suspeitas capturadas por URLScan. |
| **Abuse contacts** (ARIN) | abuse@digitalocean.com | Canal oficial de relato de abuso disponível. |

**Conclusão comportamental:**  
- Não há sinais explícitos de que o IP esteja operando como **C2**, **botnet**, ou **scanner de rede**.  
- O risco principal decorre da **exposição pública de serviços** (SSH, HTTP/HTTPS) e da **presença de múltiplas vulnerabilidades** no servidor Apache, que podem ser exploradas por atores maliciosos para comprometimento do host ou para usá‑lo como **ponto de apoio** em campanhas de ataque.

---

## 3. Superfície de Ataque  

### 3.1 Portas abertas e serviços
| Porta | Serviço | Versão / Banner |
|-------|---------|-----------------|
| **22/TCP** | OpenSSH | `9.6p1 Ubuntu-3ubuntu13.13` (ECDSA host key) |
| **80/TCP** | Apache httpd | `2.4.58 (Ubuntu)` – página “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés” |
| **443/TCP** | Apache httpd (TLS) | `2.4.58 (Ubuntu)` – certificado **Let’s Encrypt** (`convitecenturion.com`, válido até 08 Jan 2026) |

### 3.2 Vulnerabilidades (CVEs) detectadas pelo Shodan  
> *Obs.: a listagem completa contém mais de 30 CVEs. Abaixo, destacamos as mais relevantes por criticidade.*

| Severidade | CVE | Versão afetada | Resumo (CVSS) |
|------------|-----|----------------|----------------|
| **Crítica** | CVE‑2025‑53020 | Apache 2.4.17 – 2.4.63 | *Memory after effective lifetime* – risco de corrupção de memória (CVSS 7.5) |
| **Crítica** | CVE‑2025‑23048 | Apache 2.4.35 – 2.4.63 | *TLS 1.3 session‑resumption access‑control bypass* (CVSS 9.1) |
| **Crítica** | CVE‑2024‑38476 | Apache 2.4.59 – 2.4.63 | *Information disclosure / SSRF / local script exec* (CVSS 9.8) |
| **Alta** | CVE‑2025‑49812 | Apache 2.4.17 – 2.4.63 | *Mod_ssl HTTP desynchronisation via TLS upgrade* (CVSS 7.4) |
| **Alta** | CVE‑2025‑49630 | Apache 2.4.26 – 2.4.63 | *DoS via mod_proxy_http2 assertion* (CVSS 7.5) |
| **Média** | CVE‑2024‑38473 | Apache 2.4.59 – 2.4.63 | *Encoding problem in mod_proxy – auth bypass* (CVSS 8.1) |
| **Baixa** | CVE‑2013‑4365 | mod_fcgid (Apache) | *Heap‑based buffer overflow* (CVSS 7.5) |
| … | … | … | … |

> **Observação:** O Shodan não confirma a efetiva exploração de cada CVE; apenas indica que a presença da versão do Apache as **torna potencialmente vulneráveis**.  

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS14061** – *DigitalOcean, LLC* |
| **Provedor (ISP)** | DigitalOcean, LLC |
| **Organização** | DigitalOcean, LLC |
| **País** | United States (US) |
| **Região / Estado** | New Jersey |
| **Cidade** | North Bergen |
| **Coordenadas** | 40.8043 N, ‑74.0121 W |
| **Postal / ZIP** | 07047 |
| **Fuso horário** | America/New_York |
| **Domínio / Hostname** | convitecenturion.com |
| **Rede CIDR** | 161.35.0.0/16 (bloco atribuído a DigitalOcean) |
| **Contatos de abuso** | abuse@digitalocean.com (tel +1‑646‑827‑4366) |
| **Contato NOC** | noc@digitalocean.com (tel +1‑646‑827‑4366) |

---

## 5. Recomendações (próximos passos de investigação)

1. **Correlacionar com feeds de ameaças**  
   - Consultar fontes como AbuseIPDB, AlienVault OTX, VirusTotal, IPQS, e outras listas de reputação para verificar se o IP já foi relatado por comportamentos maliciosos (spam, phishing, botnet, etc.).  

2. **Analisar logs de borda**  
   - Revisar logs de firewall, IDS/IPS e proxies para identificar tráfego incomum (ex.: tentativas de exploração de CVEs, varreduras de porta, brute‑force SSH).  

3. **Teste de vulnerabilidade focado**  
   - Realizar varredura interna (ex.: Nessus, OpenVAS, Qualys) para confirmar quais das CVEs listadas são efetivamente exploráveis no ambiente.  (não se trata de mitigação, apenas de verificação).  

4. **Monitoramento contínuo**  
   - Ativar monitoramento de mudança de banners, certificado TLS e de novos serviços via Shodan/Passive DNS.  
   - Configurar alertas de eventos de login SSH (falhas e sucessos) e de alterações de arquivos críticos do Apache.  

5. **Contato com o provedor**  
   - Caso se confirme exploração ou atividade suspeita, abrir ticket de *abuse* junto à DigitalOcean com evidências coletadas (logs, CVEs explorados).  

6. **Inteligência adicional**  
   - Verificar a presença do domínio **convitecenturion.com** em serviços de reputação de URLs (PhishTank, Google Safe Browsing) para descartar uso como página de phishing ou de distribuição de malware.  
   - Explorar possíveis relacionamentos entre esse IP e outros hosts que compartilham o mesmo **ASN** ou **sub‑rede** (161.35.0.0/16) que já foram marcados como maliciosos.  

7. **Avaliar a necessidade de bloqueio temporário**  
   - Se houver indícios fortes de comprometimento ou de uso como ponto de pivot, considerar bloquear o IP nas perímeras de rede até que a fonte seja confirmada e/ou mitigada.  

---

### Considerações Finais
- O IP **161.35.50.50** não apresenta indicadores diretos de ser parte de uma botnet ou de operar como servidor C2.  
- O principal risco está na **superfície de ataque exposta** (serviços SSH e Web) e nas **vulnerabilidades conhecidas do Apache 2.4.58**, que incluem falhas de alta/critica gravidade.  
- Uma investigação aprofundada baseada nos pontos acima ajudará a determinar se o host está sendo abusado ou se representa uma ameaça potencial a terceiros.