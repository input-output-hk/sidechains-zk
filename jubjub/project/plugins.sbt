addSbtPlugin("org.jetbrains.scala" % "sbt-ide-settings"    % "1.1.1")
addSbtPlugin("ch.epfl.scala"       % "sbt-scalafix"        % "0.10.4")
addSbtPlugin("com.eed3si9n"        % "sbt-buildinfo"       % "0.10.0")
//addSbtPlugin("com.codecommit"      % "sbt-github-actions"  % "0.14.2")
addSbtPlugin("com.geirsson"        % "sbt-ci-release"      % "1.5.6")
addSbtPlugin("com.lightbend.sbt"   % "sbt-javaagent"       % "0.1.6")
addSbtPlugin("com.timushev.sbt"    % "sbt-updates"         % "0.6.1")
addSbtPlugin("com.typesafe.sbt"    % "sbt-git"             % "1.0.0")
addSbtPlugin("com.github.sbt"      % "sbt-native-packager" % "1.9.16")
addSbtPlugin("org.scalameta"       % "sbt-scalafmt"        % "2.5.0")
addSbtPlugin("com.github.sbt"      % "sbt-jni"             % "1.6.0")

addDependencyTreePlugin
