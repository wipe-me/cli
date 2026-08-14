FROM homebrew/brew:latest

RUN brew install asciinema agg \
    && brew install --cask wipe-me/tap/wipeme

WORKDIR /casts

CMD ["tail", "-f", "/dev/null"]
