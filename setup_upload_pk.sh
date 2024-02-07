#!/bin/bash

# Função para exibir a mensagem de ajuda
show_help() {
    echo "Usage: $0 [--std] [--test] [--ignore]"
    echo "  --std       Use standard settings for twine (default)"
    echo "  --test      Use Test PyPI as the repository"
    echo "  --ignore    Ignore interactive prompts"
    exit 1
}

# Parâmetros padrão
TWINE_ARGS="upload -u __token__ dist/*"

# Processar argumentos
while [ "$#" -gt 0 ]; do
    case "$1" in
        --std)
            # Usar configurações padrão
            TWINE_ARGS="upload -u __token__ dist/*"
            ;;
        --test)
            # Usar Test PyPI
            TWINE_ARGS="--repository-url https://test.pypi.org/legacy/ -u __token__ dist/*"
            ;;
        --ignore)
            # Ignorar prompts interativos
            TWINE_ARGS="--non-interactive -u __token__ dist/*"
            ;;
        *)
            # Exibir mensagem de ajuda para qualquer argumento desconhecido
            show_help
            ;;
    esac
    shift
done

# Verificar se nenhum argumento foi fornecido
if [ "$#" -eq 0 ]; then
    # Usar configurações padrão
    TWINE_ARGS="upload -u __token__ dist/*"
fi

# Instalar dependências
pip3 install --upgrade build twine

# Remover diretório dist
rm -rf dist

# Criar pacote
python3 -m build

# Fazer upload usando twine
twine $TWINE_ARGS
