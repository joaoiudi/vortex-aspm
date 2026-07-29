from google import genai

chave_api = "AQ.Ab8RN6LHXXEDNNmf4cRxRXZWKgjEkw_Vcrwb_lkT5JIVa1t7pg"
cliente = genai.Client(api_key=chave_api)

print("Modelos disponíveis para esta chave:")
for modelo in cliente.models.list():
    print(modelo.name)