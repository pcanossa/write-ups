# Relatório de Threat Intelligence – Domínio **regularizandocpf.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 2025‑10‑12 (dados da API).  

---  

## 1. Resumo Executivo
- **Domínio** registrado em **18/09/2025** (14 dias de idade) via **GoDaddy.com, LLC**.  
- **IP resolvido**: **216.238.109.50** – data center da **Vultr (AS20473 – “AS‑VULTR, US”)**, localizado no **Brasil** (conteúdo entregue a partir de São Paulo).  
- Certificado TLS emitido por **Let’s Encrypt (E7)**, válido por 89 dias a partir de 18/09/2025.  
- **Análise de reputação** (VirusTotal) aponta **10 deteções maliciosas** (phishing, malware, “malicious”), com motores como Sophos, Webroot, Fortinet, Netcraft, entre outros, classificando o domínio como **phishing** ou **malware**.  
- **URLScan.io** registra a página como **suspect** na primeira submissão (http → https‑only), mas o conteúdo exibido parece ser um blog “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”.  
- O domínio apresenta **status de registro restrito** (“client delete/renew/transfer/update prohibited”) e está **recém‑criado**, característica comum em campanhas de phishing/fraude que utilizam sites de aparência legítima para enganar vítimas.  

**Conclusão:** múltiplas fontes de inteligência classificam **regularizandocpf.com** como potencial vetor de phishing/malware. Embora o conteúdo aparente ser um blog, a alta taxa de deteções indica que o site pode estar sendo usado para coletar dados sensíveis (ex.: CPF) ou distribuir payloads maliciosos.

---  

## 2. Análise de Comportamento
| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Idade do domínio** | Registrado há 14 dias (19/09‑2025). | Domínios jovens são tipicamente usados em campanhas de curto prazo para evitar listas estáticas. |
| **Detecções no VT** | 10 marcadores (phishing, malware). | Alta probabilidade de ser usado para coleta de credenciais ou distribuição de código malicioso. |
| **Categoria nos fornecedores de segurança** | Forcepoint: “newly registered websites”; Sophos: “spyware and malware”; Webroot & AlphaMountain.ai: “Phishing”. | Consenso entre diferentes intel feeds sobre natureza fraudulenta. |
| **Tag “suspect” no URLScan** | Primeiro scan (http) recebeu a tag. | Indicador de comportamento suspeito ao acessar via HTTP (possível redirecionamento malicioso). |
| **Conteúdo apresentado** | Blog de cafés em português, título em PT‑BR. | Pode ser técnica de “look‑alike” usando conteúdo legítimo para mascarar finalidades maliciosas (e.g., página de captura de CPF). |
| **IP / ASN** | 216.238.109.50 – Vultr (AS20473). | Vultr é provedor de cloud amplamente usado por infra‑maliciosa por permitir criação rápida de servidores. |
| **Certificado TLS** | Let’s Encrypt, curto prazo (89 dias). | Certificados gratuitos são populares em campanhas de phishing por facilidade de obtenção. |
| **Status WHOIS** | “client delete/renew/transfer prohibited”. | Política de registro restritiva pode dificultar a rápida remoção ou transferência do domínio por terceiros. |

**Possíveis Vetores Maliciosos**  
- **Phishing de CPF** – o nome do domínio (`regularizandocpf.com`) sugere coleta de Cadastro de Pessoa Física, muito usado em golpes no Brasil.  
- **Distribuição de Malware** – alguns AVs marcaram como “malware”; pode haver arquivos maliciosos ocultos ou redirecionamentos a payloads.  
- **C2 ou Botnet** – ainda não há evidências diretas de comunicação de C2, mas o uso de cloud (Vultr) e a rotatividade de IPs (3 IPs únicos nos scans) sugerem possível infraestrutura de comando.  

---  

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20473 – AS‑VULTR, US** |
| **ISP / Provedor** | **Vultr, Inc.** (provedor de cloud) |
| **IP Resolvido** | 216.238.109.50 |
| **Localização** | **Brasil (São Paulo)** – PTR: `216.238.109.50.vultrusercontent.com` |
| **Serviço Web** | Apache/2.4.58 (Ubuntu) |
| **Portas/Serviços** | HTTP (80) → redireciona para HTTPS (443) |
| **Certificado TLS** | Let’s Encrypt (E7), válido até 17/12/2025, emissor “E7”. |

---  

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio analisado** | `regularizandocpf.com` | - |
| **IP principal** | `216.238.109.50` | Resolvido em todos os scans (3 IPs únicos). |
| **ASN** | `AS20473 – AS‑VULTR, US` | Vários hosts de cloud podem ser alocados ao mesmo ASN. |
| **Nameservers** | `ns53.domaincontrol.com`, `ns54.domaincontrol.com` (GoDaddy) | Não revelam infra adicional. |
| **Domínios “related” exibidos na página WHOIS** | `verisign.com`, `godaddy.com`, `domaincontrol.com`, `icann.org` | Referências institucionais, não necessariamente vinculadas ao comportamento malicioso. |
| **Outros domínios potencialmente ligados ao mesmo IP/ASN** (consulta “reverse IP” ou “passive DNS” recomendada) – **não fornecidos nos dados**. |

---  

## 5. Recomendações de Investigação
1. **Correlacionar logs de proxy/firewall** – buscar quaisquer requisições HTTP(S) para `regularizandocpf.com` ou para o IP `216.238.109.50` nos últimos 30 dias.  
2. **Analisar tráfego DNS** – verificar consultas para o domínio e para sub‑domínios gerados dinamicamente (ex.: `*.regularizandocpf.com`).  
3. **Executar sandbox** – submeter a URL (HTTPS) a um ambiente de análise (Cuckoo, CAPE, etc.) para identificar scripts, redirecionamentos ou downloads de arquivos suspeitos.  
4. **Revisar cabeçalhos HTTP** – observar possíveis cookies, parâmetros GET/POST que possam conter coleta de dados (ex.: “cpf”, “documento”).  
5. **Consultar feeds de ameaça** – buscar o IP 216.238.109.50 e o ASN AS20473 em fontes como AbuseIPDB, AlienVault OTX, Spamhaus, etc., para identificar outras vítimas ou indicadores de comprometimento.  
6. **Realizar pesquisa de “passive DNS”** – mapear outros domínios que apontam para o mesmo IP, o que pode revelar uma infraestrutura de campanha.  
7. **Monitorar a validade do certificado** – o certificado Let’s Encrypt deve ser renovado a cada 90 dias; mudanças podem indicar uso contínuo ou mudança de propósito.  
8. **Avaliar a necessidade de bloqueio de acesso** – caso a organização tenha usuários no Brasil que possam ser alvos de phishing de CPF, considerar bloqueio ou alerta de URL por políticas de segurança.  

---  

## 6. Conclusão
O domínio **regularizandocpf.com** apresenta múltiplas bandeiras de alerta: registro recente, hospedagem em infraestrutura de nuvem amplamente utilizada por atores maliciosos, e um número significativo de detecções de phishing/malware por fornecedores de inteligência. Embora o conteúdo exibido pareça inocente, o nome do domínio, a reputação negativa e a prática de criação rápida de sites de coleta de dados sugerem que ele esteja sendo usado em campanhas de fraude contra usuários brasileiros (principalmente visando o CPF).  

A recomendação principal é **monitorar e, se necessário, bloquear** o tráfego para este domínio/IP, bem como **investigar possíveis impactos internos** em logs de acesso e DNS. A continuidade da observação em feeds de ameaças e análise de comportamento futuro será crucial para determinar se a infraestrutura está sendo mantida ativa ou descartada.  