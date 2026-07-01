FROM ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab

RUN apt-get update -y && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash ctf
COPY ./src/cbc_plus_plus_2 /home/ctf/
COPY ./src/flag.txt /home/ctf/
WORKDIR /home/ctf

# Lock down /home/ctf so the ctf user cannot delete or replace files.
# File modes (555 / 444) protect the contents; the parent directory must
# also be non-writable by ctf, otherwise unlink() succeeds regardless of
# the file mode (unlink is gated by the directory's write bit).
RUN chmod 555 cbc_plus_plus_2 \
 && chmod 444 flag.txt \
 && chown root:root /home/ctf /home/ctf/cbc_plus_plus_2 /home/ctf/flag.txt \
 && chmod 555 /home/ctf

CMD socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"./cbc_plus_plus_2",su=ctf && fg
