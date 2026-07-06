# --- build stage: compile and package on JDK 25 ---
FROM amazoncorretto:25 AS build
# The Maven wrapper downloads Maven as a .tar.gz; the minimal corretto image lacks tar/gzip.
RUN yum install -y tar gzip && yum clean all
WORKDIR /app
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
COPY src/ src/
RUN ./mvnw -B -DskipTests package

# --- run stage ---
FROM amazoncorretto:25
WORKDIR /app
COPY --from=build /app/target/signing-service-0.1.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
