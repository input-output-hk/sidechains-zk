ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "2.13.10"

val `scala-2.13`        = "2.13.10"
val sidechainsZkVersion = "0.0.1"

val rootDirectory = file(".")

sbtJniCoreScope := Compile

lazy val publicationSettings = List(
  publish / skip := false,
  isSnapshot := git.gitUncommittedChanges.value || !git.gitCurrentTags.value.contains("v" + sidechainsZkVersion),
  versionScheme := Some("early-semver"),
  publishTo := {
    val nexus = "https://nexus.iog.solutions"
    if (isSnapshot.value) Some("snapshots".at(nexus + "/repository/maven-snapshot/"))
    else Some("releases".at(nexus + "/repository/maven-release/"))
  },
  credentials += Credentials(
    "Sonatype Nexus Repository Manager",
    "nexus.iog.solutions",
    sys.env.getOrElse("NEXUS_USERNAME", ""),
    sys.env.getOrElse("NEXUS_PASSWORD", "")
  ),
  version := {
    if (isSnapshot.value) sidechainsZkVersion + "-SNAPSHOT" else sidechainsZkVersion
  }
)

lazy val jubjubNative = project
  .in(file("jubjub-native"))
  .settings(
    name := "jubjub-native",
    nativeCompile / sourceDirectory := sourceDirectory.value / "native"
  )
  .settings(publicationSettings)
  .enablePlugins(JniNative)

lazy val jubjubBindings = project
  .in(file("jubjub-bindings"))
  .settings(commonSettings("jubjub-bindings"))
  .settings(libraryDependencies ++= Dependencies.testing)
  .settings(publicationSettings)
  .dependsOn(jubjubNative)

lazy val root = project
  .in(rootDirectory)
  .settings(
    name := "sidechains-zk",
    publish / skip := true
  )
  .settings(publicationSettings)
  .aggregate(
    jubjubNative,
    jubjubBindings
  )

val baseScalacOptions = Seq(
  "-unchecked",
  "-deprecation",
  "-feature",
  "-Wunused",
  "-encoding",
  "utf-8",
  "-Ymacro-annotations"
)

def commonSettings(projectName: String): Seq[sbt.Def.Setting[_]] = Seq(
  name := projectName,
  version := sidechainsZkVersion,
  crossScalaVersions := List(`scala-2.13`),
  semanticdbEnabled := true,                        // enable SemanticDB
  semanticdbVersion := scalafixSemanticdb.revision, // use Scalafix compatible version
  IntegrationTest / parallelExecution := false,
  scalacOptions ++= baseScalacOptions,
  Compile / doc / sources := Nil,
  Compile / packageDoc / publishArtifact := false,
  libraryDependencies ++= Dependencies.betterMonadicFor,
  libraryDependencies += compilerPlugin(Dependencies.kindProjectorPlugin.cross(CrossVersion.full)),
  // Only publish selected libraries.
  publish / skip := true
) ++
  inConfig(IntegrationTest)(Defaults.itSettings) ++
  inConfig(IntegrationTest)(org.scalafmt.sbt.ScalafmtPlugin.scalafmtConfigSettings) ++
  inConfig(IntegrationTest)(scalafixConfigSettings(IntegrationTest))

inThisBuild(
  List(
    isSnapshot := git.gitUncommittedChanges.value || !git.gitCurrentTags.value.contains("v" + sidechainsZkVersion),
    publishTo := {
      val nexus = "https://nexus.iog.solutions"
      if (isSnapshot.value) Some("snapshots".at(nexus + "/repository/maven-snapshot/"))
      else Some("releases".at(nexus + "/repository/maven-release/"))
    },
    credentials += Credentials(
      "Sonatype Nexus Repository Manager",
      "nexus.iog.solutions",
      sys.env.getOrElse("NEXUS_USERNAME", "kopytko"),
      sys.env.getOrElse("NEXUS_PASSWORD", "dupa")
    ),
    organization := "io.iohk.sidechains",
    developers := List(
      Developer(
        id = "AmbientTea",
        name = "Nikolaos Dymitriadis",
        email = "nikolaos.dymitriadis@iohk.io",
        url = url("https://github.com/AmbientTea")
      )
    ),
    homepage := Some(url("https://github.com/input-output-hk")),
    scmInfo := Some(
      ScmInfo(
        url("https://github.com/input-output-hk/sidechains-zk"),
        "git@github.com:input-output-hk/sidechains-zk.git"
      )
    ),
    licenses := List("Apache-2.0" -> url("http://www.apache.org/licenses/LICENSE-2.0")),
    scalaVersion := `scala-2.13`,
    scalafixScalaBinaryVersion := CrossVersion.binaryScalaVersion(
      scalaVersion.value
    ),
    resolvers ++= Seq(
      "IOG Nexus".at("https://nexus.iog.solutions/repository/maven-release/"),
      "Sonatype OSS Snapshots".at("https://oss.sonatype.org/content/repositories/snapshots")
    ),
    scalafixDependencies ++= List(
      "com.github.liancheng" %% "organize-imports" % "0.6.0",
      "com.github.vovapolu"  %% "scaluzzi"         % "0.1.23"
    )
  )
)

// For sbt-github-actions plugin
//inThisBuild(
//  List(
//    githubWorkflowJavaVersions := List(JavaSpec.temurin("19.0.2+7")),
//    githubWorkflowTargetTags ++= List("v*"),
//    githubWorkflowBuild := Seq(WorkflowStep.Sbt(List("validate"))),
//    githubWorkflowPublishPreamble := List(
//      WorkflowStep.Run(
//        commands = List(
//          "gpg --version",
//          """cat <(echo "${{ secrets.GPG_SECRET_KEY }}") | base64 --decode | gpg --batch --import"""
//        ),
//        name = Some("Prepare gpg for 'sbt publish'"),
//        cond = Some("contains(github.ref, 'v')")
//      )
//    ),
//    githubWorkflowPublish := List(
//      WorkflowStep.Run(
//        commands = List("sbt -Dsbt.gigahorse=false publish"),
//        env =
//          Map("NEXUS_USERNAME" -> "${{ secrets.NEXUS_USERNAME }}", "NEXUS_PASSWORD" -> "${{ secrets.NEXUS_PASSWORD }}"),
//        name = Some("Publish jars"),
//        cond = Some("contains(github.ref, 'v')")
//      )
//    ),
//    githubWorkflowPublishCond := Some("!contains(github.event.pull_request.labels.*.name, 'ci-off')"),
//    githubWorkflowPublishTargetBranches := List(
//      RefPredicate.StartsWith(Ref.Tag("v"))
//    )
//  )
//)

addCommandAlias(
  "validate",
  ";scalafmtSbtCheck;scalafmtCheckAll;scalafixAll --check;test;IntegrationTest/test"
)
