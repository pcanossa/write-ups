from ollama import Client
import requests
import sys
import json

client=Client()

domain_name = 'centralregularize.com' # Insira o Domínio a ser analisado aqui

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'Referer': 'https://google.com/',
    'DNT': '1',
}

virustotal_api_key = '' #Adicione sua chave de API do VirusTotal aqui

print(f"Coletando informações para o IP: {domain_name}...")

sanitized_domain = domain_name.replace('.', '_')
report_filename = f"threat_report_{sanitized_domain}.md"

try:
    # 1. Análise do WHOIS.com
    whois_response_host_info = requests.get(f'https://www.whois.com/whois/{domain_name}', headers=headers)
    whois_response_host_info.raise_for_status()  # Verifica se a requisição foi bem-sucedida
    whois_text = whois_response_host_info.text.replace('"""', '\\"\\"\\"') # Escapa aspas triplas

    # 2. Análise do Urlscan.io
    url_scan_reponse = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{domain_name}', headers=headers)
    url_scan_reponse.raise_for_status()

    # 3. Análise do Virus Total
    vt_details_response = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain_name}', headers={
        'x-apikey': {virustotal_api_key},
        'accept': 'application/json'
    })
    vt_details_response.raise_for_status()

    # Combinar todos os dados em uma única string para a IA
    combined_content = f"""
    ## DADOS COLETADOS PARA ANÁLISE DE THREAT INTELLIGENCE

    ### 1. Informações do WHOIS
    ```html
    {whois_text}
    ```

    ### 2. Informações do Urlscan.io
    ```json
    {url_scan_reponse.text}
    ```

    ### 3. Informações do VirusTotal
    ```json
    {vt_details_response.text}
    ```
    """
    
except requests.exceptions.HTTPError as e:
    print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
    print(f"URL que falhou: {e.request.url}")
    sys.exit(1)

prompt = """
Você é um especialista em Threat Intelligence. Analise os dados brutos fornecidos (em formato JSON e texto) sobre um endereço domínio e gere um relatório de inteligência de ameaças.

**Seu relatório deve conter:**
1.  **Resumo Executivo:** Um parágrafo conciso com as principais descobertas (localização, ISP, comportamento suspeito, domínios e IPs suspeitos relacionados, registros de malignidade).
2.  **Análise de Comportamento:** Avalie se há indícios de atividade maliciosa, como associação com botnets, scanners, ou servidores de C2, malware com base nos dados do Vírus Total e outras fontes.
3.  **Informações de Rede e Geográficas:**
    - **ASN:** Número e nome da organização.
    - **Provedor (ISP):** Nome do provedor.
    - **Localização:** Cidade, Região, País.
4.  **Domínios e IPs Relacionados:** Liste quaisquer domínios ou endereços IP associados ao domínio analisado que possam ser relevantes para a investigação.
5.  **Recomendações:** Sugira os próximos passos para uma investigação mais aprofundada (ex: verificar logs de firewall, procurar o IP em feeds de ameaças, etc.).
6.  Seu foco é identificar potenciais riscos e comportamentos maliciosos associados ao domínio analisado.

**Não fornecer orientação de mitigações de vulnerabilidades encontradas associadas ao domínio analisado. Seu papel é identificar comportamentos e riscos associados ao domínio analisado para proteção de outros usuários, não fornecer orientação de proteção para o sistema dele.**
**Formato:** Use Markdown e responda em **português do Brasil**.

**Sempre Iniciar o relatório com o seguinte formato de cabeçalho**
# Relatório de Threat Intelligence – Domínio **(Domínio Analisado)**

> **Fonte dos dados**: (Fontes utilizadas, ex: WHOIS.com, VirusTotal, URLScan.io).  
> **Última coleta VirusTotal**: (Data de Última Coleta).  
""".strip()

message = [
    {
        'role': 'system',
        'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts e comportamentos maliciosos.'
    },
    {
        'role': 'user',
        'content': prompt
    },
    {
      'role': 'user',
      'content': combined_content
    }
]

print(f"Analisando e gerando relatório...")
full_response = []
try:
    for part in client.chat('gpt-oss:120b-cloud', messages=message, stream=True):
      print(part['message']['content'], end='', flush=True)
      content = part['message']['content']
      full_response.append(content)
except Exception as e:
    print(f"\n\nErro ao comunicar com o modelo de IA: {e}")
    sys.exit(1)

print(f"\n\n--- Fim da Análise ---")

with open(report_filename, "w", encoding="utf-8") as f:
    f.write("".join(full_response))

print(f"[+] Relatório salvo com sucesso em: {report_filename}")
