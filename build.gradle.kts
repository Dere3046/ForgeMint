val moduleId by extra("forge_store")
val moduleName by extra("Forge Store")
val verName by extra("v0.7.5")
val verType by extra("-Dev")
val verCode by extra(
    providers.exec {
        commandLine("git", "rev-list", "HEAD", "--count")
    }.standardOutput.asText.get().trim().toInt()
)
val verHash by extra(
    providers.exec {
        commandLine("git", "rev-parse", "--verify", "--short", "HEAD")
    }.standardOutput.asText.get().trim()
)