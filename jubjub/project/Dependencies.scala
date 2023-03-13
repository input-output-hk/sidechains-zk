import sbt._

object Dependencies {

  val betterMonadicFor: Seq[ModuleID] = Seq(compilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1"))

  val cats: Seq[ModuleID]    = Seq("org.typelevel" %% "cats-core" % "2.9.0")
  val kittens: Seq[ModuleID] = Seq("org.typelevel" %% "kittens" % "3.0.0-M3")

  val catsStack: Seq[ModuleID] = cats ++ kittens ++
    Seq(
      "org.typelevel" %% "cats-effect"         % "3.4.5",
      "org.typelevel" %% "cats-effect-testkit" % "3.4.5" % Test,
      "org.typelevel" %% "log4cats-core"       % "2.5.0",
      "org.typelevel" %% "log4cats-slf4j"      % "2.5.0",
      "org.typelevel" %% "log4cats-noop"       % "2.5.0" % Test
    )

  val catsRetry: Seq[ModuleID] = Seq("com.github.cb372" %% "cats-retry" % "3.1.0")

  val circe: Seq[ModuleID] = {
    val circeVersion = "0.14.3"
    Seq(
      "io.circe" %% "circe-core"           % circeVersion,
      "io.circe" %% "circe-generic"        % circeVersion,
      "io.circe" %% "circe-parser"         % circeVersion,
      "io.circe" %% "circe-generic-extras" % circeVersion,
      "io.circe" %% "circe-literal"        % circeVersion
    )
  }

  val crypto: Seq[ModuleID] = Seq("org.bouncycastle" % "bcprov-jdk15on" % "1.70")

  val enumeratum: Seq[ModuleID] = Seq(
    "com.beachape" %% "enumeratum"      % "1.7.2",
    "com.beachape" %% "enumeratum-cats" % "1.7.2"
  )

  val fs2Stack: Seq[ModuleID] = {
    val fs2Version = "3.5.0"
    Seq(
      "co.fs2" %% "fs2-core"             % fs2Version,
      "co.fs2" %% "fs2-reactive-streams" % fs2Version,
      "co.fs2" %% "fs2-io"               % fs2Version,
      "co.fs2" %% "fs2-scodec"           % fs2Version
    )
  }

  val kindProjectorPlugin: ModuleID = "org.typelevel" % "kind-projector" % "0.13.2"

  val logging: Seq[ModuleID] = Seq(
    "ch.qos.logback"      % "logback-classic" % "1.4.5",
    "org.codehaus.janino" % "janino"          % "3.1.9"
  )

  val munit: Seq[ModuleID] = Seq(
    "org.scalameta" %% "munit"               % "0.7.29" % Test,
    "org.typelevel" %% "munit-cats-effect-3" % "1.0.7"  % Test
  )

  val newtype: Seq[ModuleID] = Seq("io.estatico" %% "newtype" % "0.4.4")

  val openTelemetry: Seq[ModuleID] = {
    val provider = "io.opentelemetry"
    val version  = "1.22.0"
    Seq(
      provider % "opentelemetry-api"           % version,
      provider % "opentelemetry-sdk"           % version,
      provider % "opentelemetry-exporter-otlp" % version
    )
  }

  val shapeless: Seq[ModuleID] = Seq("com.chuusai" %% "shapeless" % "2.3.10")

  val scalaCheck: ModuleID = "org.scalacheck" %% "scalacheck" % "1.17.0"

  val itTesting: Seq[ModuleID] = Seq(
    "org.scalatest" %% "scalatest" % "3.2.15" % "it",
    scalaCheck       % "it"
  )

  val testing: Seq[ModuleID] = Seq(
    "org.scalatest"     %% "scalatest"       % "3.2.15",
    "org.scalatestplus" %% "scalacheck-1-17" % "3.2.15.0",
    scalaCheck,
    "com.softwaremill.diffx" %% "diffx-scalatest-should" % "0.8.2"
  ).map(_ % Test)

  val doobie: Seq[ModuleID] = {
    val version = "1.0.0-RC2"
    Seq(
      "org.tpolecat" %% "doobie-core"     % version,
      "org.tpolecat" %% "doobie-hikari"   % version, // HikariCP transactor.
      "org.tpolecat" %% "doobie-postgres" % version  // Postgres driver 42.3.1 + type mappings.
    )
  }

  val dbTesting: Seq[ModuleID] = {
    val version = "0.40.12"
    Seq(
      "com.dimafeng" %% "testcontainers-scala-scalatest"  % version  % IntegrationTest,
      "com.dimafeng" %% "testcontainers-scala-postgresql" % version  % IntegrationTest,
      "org.flywaydb"  % "flyway-core"                     % "9.14.0" % IntegrationTest
    )
  }

  val trace4cats: Seq[ModuleID] = {
    val version = "0.14.1"
    Seq(
      "io.janstenpickle" %% "trace4cats-core"                             % version,
      "io.janstenpickle" %% "trace4cats-inject"                           % version,
      "io.janstenpickle" %% "trace4cats-opentelemetry-otlp-http-exporter" % version
    )
  }

  val quicklens: Seq[ModuleID] = Seq(
    "com.softwaremill.quicklens" % "quicklens_2.13" % "1.8.10"
  )

  val pureConfig: Seq[ModuleID] = Seq("com.github.pureconfig" %% "pureconfig" % "0.17.2")
}
