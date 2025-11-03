FROM openjdk:24-slim

COPY build/libs/spring-authorization-server-1.0.jar app.jar

EXPOSE 8090

ENTRYPOINT ["java", "-jar", "app.jar"]