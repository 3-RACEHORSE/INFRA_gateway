FROM bellsoft/liberica-openjdk-alpine:17 as build
WORKDIR /workspace/app

# Copy the built JAR file
COPY build/libs/*.jar .

# Unpack the built application
RUN mkdir -p target/extracted
RUN java -Djarmode=layertools -jar *.jar extract --destination target/extracted

FROM bellsoft/liberica-openjdk-alpine:17
VOLUME /tmp
ARG EXTRACTED=/workspace/app/target/extracted
ARG KAFKA_BOOTSTRAP_SERVERS
ENV KAFKA_BOOTSTRAP_SERVERS=${KAFKA_BOOTSTRAP_SERVERS}

# Copy over the unpacked application
COPY --from=build ${EXTRACTED}/dependencies/ ./
COPY --from=build ${EXTRACTED}/spring-boot-loader/ ./
COPY --from=build ${EXTRACTED}/snapshot-dependencies/ ./
COPY --from=build ${EXTRACTED}/application/ ./

ENTRYPOINT ["java","org.springframework.boot.loader.JarLauncher"]