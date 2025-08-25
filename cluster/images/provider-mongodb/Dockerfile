ARG CONTAINER_REGISTRY=iaactmpreg.azurecr.io

FROM $CONTAINER_REGISTRY/acp/base-container-image:0.2.1

ARG PROVIDER_NAME
ARG TARGETOS
ARG TARGETARCH

ADD bin/${TARGETOS}_${TARGETARCH}/${PROVIDER_NAME}-controller /usr/local/bin/${PROVIDER_NAME}-controller
RUN chmod +x /usr/local/bin/${PROVIDER_NAME}-controller

# Docker doesn't support string interpolation in its ENTRYPOINT statement, hence this hack
# More info: https://github.com/moby/moby/issues/18492
RUN ln -s /usr/local/bin/${PROVIDER_NAME}-controller controller

USER 65532
ENTRYPOINT ["./controller"]