# Relatório de Threat Intelligence – Domínio **portalregularizacao.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 22 / 09 / 2025 (epoch 175 849 9200).  

---  

## 1. Resumo Executivo
- **Domínio** registrado em 22 / 09 / 2025 via GoDaddy (registrar ID 146) com política de **“client delete/renew/transfer/update prohibited”**.  
- **IP principal:** 216.238.109.50, pertencente à **AS 20473 – VULTR (EE. UU.)**.  
- **Serviço web:** Apache 2.4.58 sobre Ubuntu, certificado Let’s Encrypt emitido em 22 / 09 / 2025 (validade ≈ 89 dias).  
- **Análises de reputação:** 0 malicious, 0 suspicious; 61 harmless, 34 undetected (VT). Nenhum motor apontou atividade maliciosa.  
- **Tag “suspect”** aplicada pelo URLScan.io, porém sem evidência clara de comportamento nocivo.  
- **Objetivo aparente da página:** blog de café (“Giovani e Adenir Oliveira – Blog Veroo Cafés”).  

**Conclusão preliminar:** o domínio apresenta perfil “limpo” nas principais bases de inteligência, porém é recém‑registrado, hospedado em VPS de uso genérico (Vultr) e recebeu a classificação “suspect” por heurística do URLScan. Recomenda‑se vigilância continuada para detectar eventual mudança de comportamento (ex.: uso futuro como C2, phishing ou distribuição de malware).

---  

## 2. Análise de Comportamento
| Fonte | Indicador | Avaliação |
|-------|-----------|-----------|
| **VirusTotal** | 0 malicious / 0 suspicious | Não há detecção ativa. A maioria dos engines classifica como *harmless* ou *undetected*. |
| **URLScan.io** | Tag *suspect*; 29 requisições, 3 IPs distintos, 2 países (BR + US) | A tag indica que o scanner considerou o conteúdo ou a configuração (ex.: redirecionamento “https‑only”, uso de CDN/Vultr) como possivelmente suspeito, porém não há evidência de phishing ou carga maliciosa. |
| **Whois** | Registrado recentemente, dados do registrante ofuscados (strings aleatórias) | Privacidade de registro pode ser padrão de “privacy protection” ou tentativa de ocultar identidade – comportamento comum a sites legítimos e a atores maliciosos. |
| **Infraestrutura** | Servidor Apache/Ubuntu, certificado Let’s Encrypt, IP em data‑center Vultr | Configuração típica de sites pequenos/blogs. Não há indícios de infraestrutura de botnet ou C2 (ex.: comunicação de saída incomum, portas não‑padrão). |
| **Conteúdo observado** | Título indica blog de café, linguagem em português (pt) | Não há indícios de phishing, fraude ou payloads. O conteúdo parece legítimo. |

### Possíveis Vetores de Risco Futuro
1. **Uso como “dropper”** – domínios recém‑criados podem ser reutilizados para hospedar arquivos maliciosos ou redirecionar tráfego.  
2. **Phishing** – a presença de certificado válido facilita a criação de páginas de coleta de credenciais.  
3. **C2 ou “loader”** – servidores em VPS (Vultr) são comumente usados por ameaças para comunicação de comando e controle; monitoramento de tráfego de saída pode revelar mudanças.  

---  

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20473 – VULTR** (United States) |
| **ISP / Provedor** | **Vultr, Inc.** (provedor de cloud/VPS) |
| **Endereço IP** | 216.238.109.50 |
| **Localização Aproximada** | **Estados Unidos** – (Datacenter Vultr, provável região: **Estados‑Unidos – região NA (ex.: Dallas, TX / Phoenix, AZ)**) |
| **Cidade / Região** | Não especificado (dados de geolocalização indicam apenas “United States”). |
| **País** | **EE. UU.** |
| **Nome do Servidor (PTR)** | 216.238.109.50.vultrusercontent.com |
| **Nome dos Servidores DNS** | ns63.domaincontrol.com, ns64.domaincontrol.com (GoDaddy) |

---  

## 4. Domínios e IPs Relacionados
- **IPs observados pelo URLScan.io (uniqIPs = 3):**  
  - 216.238.109.50 (principal)  
  - (outros dois IPs não explicitados nos metadados, possivelmente associados a recursos externos ‑ CDN, imagens, scripts).  
- **Domínios / Nameservers associados:**  
  - `ns63.domaincontrol.com`  
  - `ns64.domaincontrol.com`  
- **Domínios de referência na página (conforme título):**  
  - Nenhum sub‑domínio interno detectado; a página parece ser de um único host.  
- **Domínios “relacionados” exibidos pelo WHOIS.com:**  
  - `verisign.com` – (registro de TLD)  
  - `godaddy.com` – (registrar)  
  - `domaincontrol.com` – (nome dos servidores DNS)  
  - `icann.org` – (referência institucional)  

---  

## 5. Recomendações de Investigação
1. **Monitoramento de DNS e IP**  
   - Configurar alertas para quaisquer alterações nos **registros A/AAAA**, **NS** e **TXT** (ex.: SPF, DKIM).  
   - Verificar alterações de **ASN** ou mudança de provedor de hospedagem.  

2. **Análise de Tráfego de Rede**  
   - Capturar e analisar fluxos de saída do IP 216.238.109.50 (ex.: NetFlow, Zeek) para detectar padrões de comunicação incomuns (ex.: conexões para destinos de alta reputação de C2).  

3. **Verificação de Conteúdo Web**  
   - Realizar varredura periódica com scanners de malware/web (ex.: **Crawling + ClamAV, Maltrail) para identificar arquivos ou scripts maliciosos inseridos posteriormente.**  
   - Avaliar o *DOM* da página para possíveis *iframes* ou *obfuscation* que possam ser inseridos depois.  

4. **Checagem em Feeds de Inteligência**  
   - Consultar **AbuseIPDB, AlienVault OTX, Spamhaus, URLhaus** e **ThreatCrowd** para o IP e domínio em tempo real.  
   - Incluir o domínio em uma lista de observação interna (STIX/OPEN‑CTI).  

5. **Análise de Certificado**  
   - Monitorar a renovação do certificado Let’s Encrypt (a cada 90 dias) – mudanças de *CN* ou *SAN* podem indicar abuso.  

6. **Verificação de Phishing**  
   - Utilizar serviços como **PhishTank**, **Google Safe Browsing** e **Microsoft Defender SmartScreen** para detectar relatórios de phishing associados ao domínio.  

7. **Correlacionar com Incidentes Internos**  
   - Caso existam eventos de conexão de usuários internos ao IP 216.238.109.50, investigar logs de firewall, proxy e endpoint para possíveis compromissos.  

---  

*Este relatório resume a situação conhecida até a data da coleta. Como o domínio é recente e ainda não foi marcado como malicioso pelos principais repositórios, o risco atual parece baixo, porém a classificação “suspect” do URLScan indica que a atenção contínua é prudente.*  