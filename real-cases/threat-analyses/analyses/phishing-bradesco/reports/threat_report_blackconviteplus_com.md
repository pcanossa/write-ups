# Relatório de Threat Intelligence – Domínio **blackconviteplus.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 04/10/2025 (Unix 1759680259).  

---

## 1. Resumo Executivo
O domínio **blackconviteplus.com** foi registrado em 03/10/2025 (registro 0 dias) via GoDaddy e aponta para o IP **191.252.227.30**, pertencente à operadora **Locaweb Serviços de Internet S/A (AS27715, Brasil)**. O site hospeda um blog em português sobre “Veroo Cafés”, porém o nome do domínio não possui relação aparente com o conteúdo, indicando possível uso de *domain‑parking* ou de *camuflagem* para fins de phishing ou spam. Nenhuma detecção de malware ou classificação de reputação foi encontrada nos 95 scanners da VirusTotal; o domínio aparece como *undetected* em todas as bases. Apesar da ausência de sinais claros de atividade maliciosa, a combinação de **registro recente**, **IP de data‑center compartilhado**, e **nome de domínio não correlacionado ao conteúdo** sugere cautela e monitoramento contínuo.

---

## 2. Análise de Comportamento
| Item | Evidência | Interpretação |
|------|-----------|---------------|
| **Registro recente** (0 dias) | Data de criação 03/10/2025 | Domínios recém‑criados são frequentemente usados em campanhas de phishing, malware ou esquemas de *spam* antes que sejam listados em blocklists. |
| **Conteúdo do site** | Título “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés” | O conteúdo público parece legítimo, porém não tem relação com a palavra “blackconviteplus”, indicando possível tentativa de *camuflagem* (uso de domínio genérico para atrair cliques). |
| **Server/Stack** | Apache 2.4.52 (Ubuntu) | Software padrão, sem vulnerabilidades específicas observadas. |
| **TLS** | Certificado Let’s Encrypt (válido 89 dias, emitido 03/10/2025) | Certificado recente, normalmente usado por sites legítimos, mas também por atores maliciosos para dar aparência de confiança. |
| **IP/ASN** | 191.252.227.30 — AS27715 (Locaweb, BR) | Data‑center brasileiro que hospeda múltiplos clientes; IP pode ser compartilhado por diversos domínios. |
| **VirusTotal** | 95/95 scanners – *undetected*; nenhuma marcação de *malicious*, *suspicious* ou *phishing* | Não há indicações de malware conhecido ou de atividades de C2. |
| **Listas de bloqueio** | Nenhum engine (Acronis, Kaspersky, etc.) reportou o domínio como malicioso | Ainda não reputado como ameaça, mas o monitoramento é essencial devido à nova criação. |
| **DNS** | NS ns49.domaincontrol.com / ns50.domaincontrol.com (GoDaddy) | Servidor DNS padrão de registrador; não indica uso de infra‑estrutura de ameaças. |

**Conclusão comportamental:** Não há evidências diretas de uso como *botnet*, *C2* ou *phishing* ativo. Contudo, o perfil (registro novo, domínio sem relação ao conteúdo hospedado, hospedagem em data‑center compartilhado) é típico de **domínios “cobertos”** que podem ser ativados para campanhas maliciosas rápidas antes de serem detectados.

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS27715 – Locaweb Serviços de Internet S/A** |
| **ISP / Provedor** | **Locaweb Serviços de Internet S/A** |
| **IP** | **191.252.227.30** |
| **País** | **Brasil (BR)** |
| **Estado / Região** | Não especificado (localização de IP indica São Paulo‑SP, mas pode variar) |
| **Cidade** | **São Paulo** (baseado em geolocalização de ASN) |
| **Nome do Servidor Web** | Apache/2.4.52 (Ubuntu) |
| **Portas relevantes** | 80 (HTTP), 443 (HTTPS) – certificado Let’s Encrypt (R13) |
| **Domínio de nível superior** | **.com** |
| **Data de registro** | **03/10/2025** |
| **Data de expiração** | **03/10/2026** |
| **Nameservers** | ns49.domaincontrol.com, ns50.domaincontrol.com (GoDaddy) |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **IP primário** | 191.252.227.30 | Hospeda o site do domínio analisado. |
| **Nameservers** | ns49.domaincontrol.com, ns50.domaincontrol.com | Servidores DNS do registrador GoDaddy. |
| **Domínios associados ao mesmo IP** | (não fornecidos nos dados) – recomenda‑se consulta a *Reverse IP lookup* (e.g., securitytrails, censys.io) para identificar outros hosts no mesmo IP. |
| **Domínios “sibling”** | Nenhum outro domínio listado no WHOIS ou VT. |

---

## 5. Recomendações de Investigação
1. **Monitoramento de reputação**  
   - Inscrever o domínio/ IP em plataformas de *threat intel* (e.g., VirusTotal Watch, AbuseIPDB, Hybrid Analysis) para receber alertas de futuras detecções.  

2. **Correlações de IP**  
   - Realizar pesquisa *reverse‑IP* para descobrir outros domínios que compartilham o IP **191.252.227.30**; analisar se algum deles já consta em listas de bloqueio ou já foi usado em campanhas de phishing.  

3. **Análise de tráfego**  
   - Verificar logs de firewall/proxy para conexões HTTP/HTTPS ao domínio ou ao IP nas últimas 30‑60 dias; identificar padrões de acesso suspeitos (picos incomuns, User‑Agents raros, geolocalizações fora do Brasil).  

4. **Varredura de conteúdo**  
   - Executar *web‑site crawling* (e.g., `wget`, `gobuster`) para coletar recursos ocultos, scripts ou arquivos de configuração que possam indicar funcionalidades de *phishing* ou *malware distribution*.  

5. **Checagem de certificados**  
   - Monitorar a renovação do certificado Let’s Encrypt; mudanças repentinas no CN ou emissor podem indicar abandono ou transferência do controle.  

6. **Inteligência de DNS**  
   - Configurar consultas periódicas de DNS (A, MX, TXT, SPF, DMARC) para detectar alterações – por exemplo, inclusão de registros MX suspeitos ou mudanças de nameserver que apontem a um provedor de hospedagem de baixo custo usado por atores maliciosos.  

7. **Análise de WHOIS e RDAP**  
   - Confirmar a identidade do registrante (GoDaddy) e validar o contato de abuso (`abuse@godaddy.com`). Caso haja suspeita de uso malicioso, notificar o registrador.  

8. **Observação de atividades de phishing**  
   - Consultar bases públicas de phishing (PhishTank, OpenPhish) usando o domínio como termo de busca; caso o domínio apareça, iniciar bloqueio imediato.  

---

## 6. Conclusão
Embora o domínio **blackconviteplus.com** não apresente sinais de comprometimento ativo nas fontes analisadas, seu *registro recente*, a discrepância entre nome e conteúdo, e a hospedagem em um data‑center compartilhado justificam um **nível de risco moderado**. Recomenda‑se manter vigilância constante e aplicar as ações de investigação listadas para detectar possíveis mudanças de comportamento que possam transformar o domínio em um vetor de ataque.  

---