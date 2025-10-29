# Relatório de Threat Intelligence – Domínio **blackconvitevip.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal (API v3).  
> **Última coleta VirusTotal**: 27 / 09 / 2025 18:20 UTC.  

---

## 1. Resumo Executivo
O domínio **blackconvitevip.com** foi registrado em 26 / 09 / 2025 (registro de apenas 1 dia) via GoDaddy e aponta para o IP **191.252.225.147**, hospedado na Locaweb Serviços de Internet (ASN **AS27715**) – provedor brasileiro. O site exibe um blog em português e utiliza certificado Let’s Encrypt válido por 89 dias.  

Análises de Inteligência de Ameaças revelam **indicadores de atividade maliciosa**:  
- **4 engines de AV/VTI** marcam o domínio como **malicious** (CRDF, CyRadar, Lionic – phishing, Google Safebrowsing – phishing).  
- **1 engine** classifica como **suspicious** (Gridinsoft).  
- O domínio aparece com a tag **“suspect”** no URLScan.io.  
- O endereço IP tem **PTR “vpscl3417.publiccloud.com.br”**, tipicamente associado a VPS de uso genérico, mas sem histórico público de reputação limpa.  

Esses sinais apontam para **possível infraestrutura de phishing ou de campanha de engenharia social**, possivelmente usada para enganar usuários brasileiros.

---

## 2. Análise de Comportamento
| Fonte | Indicador | Interpretação |
|-------|-----------|---------------|
| **VirusTotal – Last analysis results** | CRDF (malicious), CyRadar (malicious), Google Safebrowsing (phishing), Lionic (phishing) | Várias plataformas de threat intel identificam o domínio como fonte de phishing. |
| **VirusTotal – last_analysis_stats** | Malicious = 4, Suspicious = 1, Harmless = 58, Undetected = 32 | Percentual de detecção de comportamento maligno > 6 % (acima da média para domínios recém‑criados). |
| **URLScan.io** | Tag “suspect”, domínio recém‑criado (0‑1 dia), TLS recém‑emitido (validade 89 dias) | Implantação rápida de site com TLS legítimo (Let’s Encrypt) – prática comum em campanhas de phishing para aumentar confiança. |
| **Servidor HTTP** | Apache/2.4.52 (Ubuntu) | Servidor padrão, comum em ambientes de VPS. |
| **Conteúdo da página** | Blog “Veroo Cafés” com texto em português; porém, a página pode ser usada como “landing page” para captura de credenciais ou redirecionamento malicioso. | Conteúdo aparentemente inocente, mas pode ser camuflagem para enganar vítimas. |
| **Portas e Serviços** | Apenas HTTP/HTTPS (porta 80/443). | Não há serviços adicionais expostos, reduzindo a superfície de ataque, porém facilita uso como ponto de entrega (C2 ou phishing). |
| **ASN / ISP** | Locaweb Servicos de Internet SA (AS27715) – provedor brasileiro que oferece VPS compartilhados. | Vários casos de abuso de VPSs de provedores de hospedagem para hospedagem de sites de phishing. |

**Conclusão:** Os indicadores apontam fortemente para um **site de phishing** recém‑implantado, possivelmente parte de um **campanha de engenharia social dirigida ao público brasileiro**. O uso de certificado válido e conteúdo em língua local são táticas para aumentar a credibilidade.

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS27715 – Locaweb Serviços de Internet SA** |
| **Provedor (ISP)** | **Locaweb Serviços de Internet SA** (Brasil) |
| **IP** | **191.252.225.147** |
| **PTR (Reverse DNS)** | **vpscl3417.publiccloud.com.br** |
| **Localização** | **Brasil – Estado não especificado (provável região Sudeste)** |
| **Cidade** | Não disponível (dados de geolocalização apontam apenas ao país) |
| **Região** | América do Sul |
| **País** | **Brasil (BR)** |
| **Portas/Serviços Expostos** | HTTP (80), HTTPS (443) – Apache/2.4.52 (Ubuntu) |
| **Data de criação do domínio** | **26 / 09 / 2025** (há 1 dia) |
| **Data de emissão do certificado TLS** | **26 / 09 / 2025**, validade até **25 / 12 / 2025** (89 dias) |
| **Nome do servidor Web** | **Apache/2.4.52 (Ubuntu)** |
| **Nome do domínio (apex)** | **blackconvitevip.com** |
| **Nameservers** | ns41.domaincontrol.com, ns42.domaincontrol.com (GoDaddy) |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **IP associado** | 191.252.225.147 | Único IP encontrado nas duas varreduras do URLScan.io. |
| **PTR** | vpscl3417.publiccloud.com.br | Indica VPS em data center da Locaweb (publiccloud). |
| **Outros domínios no mesmo IP** | *Não disponíveis nos dados fornecidos.* Recomenda‑se consulta a bases de dados de passive DNS ou Shodan/ZoomEye para identificar “siblings”. |
| **Domínios listados nas tags/profiles** | Nenhum adicional listado além do próprio domínio. |
| **Serviços associados** | Let’s Encrypt (R12) – emissor do certificado TLS. |
| **Possíveis alvos** | Público brasileiro, especialmente usuários que buscam “convite VIP” ou conteúdo de blog de cafés. |

---

## 5. Recomendações de Investigação

| Ação | Rationale |
|------|-----------|
| **1. Consulta a feeds de inteligência de phishing** (PhishTank, OpenPhish, APWG) para confirmar presença do domínio. | Vários engines já rotularam como phishing; validar se já está listado em listas públicas. |
| **2. Busca em bases de passive DNS** (PassiveTotal, SecurityTrails) para identificar outros domínios que compartilham o IP 191.252.225.147 ou o PTR. | Pode revelar campanha de domínio “parking” ou farm de phishing. |
| **3. Análise de histórico de IP** (Shodan, Censys, GreyNoise). | Verificar se o IP já esteve associado a atividades maliciosas anteriores ou se hospeda outros sites suspeitos. |
| **4. Verificação de logs de firewall e proxy** da organização que recebeu alertas, procurando conexões DNS/HTTP para **blackconvitevip.com** ou **191.252.225.147**. | Detectar se há tráfego interno direcionado ao site e avaliar impacto. |
| **5. Captura de artefatos de página** (HTML, JavaScript) via URLScan.io ou sandbox (e.g., Any.Run) para identificar redirecionamentos, coleta de credenciais ou downloads maliciosos. | Confirmar a presença de scripts de coleta de dados ou de download de payload. |
| **6. Contato com o provedor (Locaweb)** via abuse@locaweb.com.br, apresentando evidências de phishing. | Possibilidade de ação de remoção ou suspensão do serviço. |
| **7. Monitoramento de reputação** do domínio e IP em futuras atualizações de VT, AlienVault OTX, AbuseIPDB. | Detectar mudanças de classificação ou novos indicadores. |
| **8. Enriquecimento de indicadores** (hashes de arquivos, URLs internas) caso sejam descobertos artefatos de malware. | Facilitar correlação com outras campanhas. |

> **Nota:** Todas as recomendações são focadas em **investigar** e **correlacionar** o domínio com possíveis ameaças, sem instruir sobre mitigação direta.

---

*Este relatório foi elaborado com base nas informações públicas disponíveis até a data de coleta e tem como objetivo auxiliar equipes de segurança na avaliação de risco e na condução de investigações adicionais.*