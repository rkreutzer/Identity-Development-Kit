import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pack_ci", Path(__file__).with_name("pack_ci.py"))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class PackCiTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        for pack in ci.PACKS:
            path = root / pack / "lib" / pack
            path.mkdir(parents=True)
            (path / "build.gradle.kts").write_text("", encoding="utf-8")
            (root / pack / "settings.gradle.kts").write_text(
                f'includeLocal("lib-{pack}", "lib/{pack}")\n', encoding="utf-8")
        return root

    def prerequisite_environment(self):
        return {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": ci.PRIVATE_REPOSITORY,
                "GITHUB_REF_NAME": "codex/infra-owned-workspaces", "GITHUB_REF": "refs/heads/codex/infra-owned-workspaces"}

    def selected_fixture(self, directory):
        root = self.fixture(directory)
        (root / "platform-version.properties").write_text("platformVersion=0.26.0-SNAPSHOT")
        for pack in ci.PACKS:
            (root / pack / "lib" / pack / "build.gradle.kts").write_text(
                'plugins { alias(sphereonplug.plugins.com.vanniktech.maven.publish) }')
        return root

    def testSelectedPublicationRecognizesOwningRestAndKmsPluginDeclarations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.selected_fixture(directory)
            (root / "protocols/lib/protocols/build.gradle.kts").write_text(
                "plugins { `maven-publish` }")
            (root / "identity-security/lib/identity-security/build.gradle.kts").write_text(
                "plugins { alias(sphereonplug.plugins.com.sphereon.gradle.plugin.project.publication) }")
            stages = ci.plan(root, "private", True, self.prerequisite_environment(),
                             snapshot_prerequisites_only=True,
                             publish_modules="lib-protocols,lib-identity-security")
            self.assertEqual(["prepare"] * 6 + ["check", "check", "publish", "publish"], [s["phase"] for s in stages])
            checks = [s for s in stages if s["phase"] == "check"]
            self.assertEqual({"protocols", "identity-security"}, {s["pack"] for s in checks})
            self.assertTrue(all(s["tasks"] == ["build"] for s in checks))

    def testSelectedPublicationRejectsUnrelatedAndCommentedPublisherDeclarations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.selected_fixture(directory)
            for declaration in ["plugins { `npm-publish` }",
                                "plugins { alias(sphereonplug.plugins.com.sphereon.gradle.plugin.service.deployable) }",
                                "// plugins { `maven-publish` }",
                                "/* alias(sphereonplug.plugins.com.sphereon.gradle.plugin.project.publication) */"]:
                (root / "protocols/lib/protocols/build.gradle.kts").write_text(declaration)
                with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, "Maven publication plugin"):
                    ci.plan(root, "private", True, self.prerequisite_environment(),
                            snapshot_prerequisites_only=True, publish_modules="lib-protocols")

    def testSelectedPublicationPreparesPeerApisAndRemainsBounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.selected_fixture(directory)
            stages = ci.plan(root, "private", True, self.prerequisite_environment(),
                             snapshot_prerequisites_only=True, publish_modules="lib-protocols,lib-protocols")
            self.assertEqual(["prepare"] * 6 + ["check", "publish"], [s["phase"] for s in stages])
            self.assertEqual(list(ci.PACKS), [s["pack"] for s in stages[:6]])
            self.assertTrue(all(s["tasks"] == ["publishAllPublicationsToCiPrerequisitesRepository"] for s in stages[:6]))
            self.assertEqual(["build"], stages[6]["tasks"])
            self.assertEqual([":lib-protocols:publishAllPublicationsToSphereon-opensourceRepository"], stages[7]["tasks"])
            for stage in stages:
                args = ci.command(root, stage, "private", root / "job-private")
                self.assertNotIn("-Didk.ci.remote-only=true", args)
                self.assertNotIn("--no-build-cache", args)
                self.assertNotIn("publishCiMavenRemote", args)
            self.assertIn("-Didk.ci.publish=true", ci.command(root, stages[7], "private", root / "job-private"))

    def testSelectedPublicationRejectsInvalidNamesFlagsAndNonMavenModules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.selected_fixture(directory)
            env = self.prerequisite_environment()
            for names in ["unknown", ":lib-core", "lib-core:publish", "lib-core --foo", "lib-core,", "../core"]:
                with self.subTest(names=names), self.assertRaises(ValueError):
                    ci.plan(root, "private", True, env, snapshot_prerequisites_only=True, publish_modules=names)
            for mode, publish, remote, snapshot in [("public", True, False, True), ("private", False, False, True),
                                                    ("private", True, True, True), ("private", True, False, False)]:
                with self.assertRaises(ValueError):
                    ci.plan(root, mode, publish, env, remote, snapshot, "lib-core")
            for bad_env in [env | {"GITHUB_REF": "refs/heads/main"}, env | {"GITHUB_EVENT_NAME": "push"}]:
                with self.assertRaises(ValueError):
                    ci.plan(root, "private", True, bad_env, snapshot_prerequisites_only=True, publish_modules="lib-core")
            (root / "core/lib/core/build.gradle.kts").write_text("// maven-publish is not an applied plugin")
            with self.assertRaisesRegex(ValueError, "Maven publication plugin"):
                ci.plan(root, "private", True, env, snapshot_prerequisites_only=True, publish_modules="lib-core")
            (root / "platform-version.properties").write_text("platformVersion=0.26.0")
            with self.assertRaisesRegex(ValueError, "SNAPSHOT"):
                ci.plan(root, "private", True, env, snapshot_prerequisites_only=True, publish_modules="lib-protocols")

    def testSelectedChecksAcrossPacksBlockEveryPublicationOnFailure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.selected_fixture(directory)
            stages = ci.plan(root, "private", True, self.prerequisite_environment(),
                             snapshot_prerequisites_only=True, publish_modules="lib-core,lib-protocols")
            self.assertEqual(["prepare"] * 6 + ["check", "check", "publish", "publish"], [s["phase"] for s in stages])
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                self.assertTrue(kwargs["check"])
                if "build" in command:
                    raise ci.subprocess.CalledProcessError(7, command)
            with patch.dict(os.environ, {"NEXUS_USERNAME": "test", "NEXUS_PASSWORD": "test"}):
                with self.assertRaises(ci.subprocess.CalledProcessError):
                    ci.execute(root, stages, "private", root / "unused", runner=runner)
            self.assertEqual(8, len(calls))
            self.assertEqual(2, sum("build" in c for c in calls))
            self.assertTrue(all("-Didk.ci.publish=false" in c for c in calls))

    def testSelectedPreparationFailureForbidsChecksAndEveryRemotePublication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.selected_fixture(directory)
            stages = ci.plan(root, "private", True, self.prerequisite_environment(),
                             snapshot_prerequisites_only=True, publish_modules="lib-protocols")
            calls = []
            def fail(command, **kwargs):
                calls.append(command)
                raise ci.subprocess.CalledProcessError(11, command)
            with patch.dict(os.environ, {"NEXUS_USERNAME": "test", "NEXUS_PASSWORD": "test"}):
                with self.assertRaises(ci.subprocess.CalledProcessError):
                    ci.execute(root, stages, "private", root / "job-private", runner=fail)
            self.assertEqual(1, len(calls))
            self.assertIn("publishAllPublicationsToCiPrerequisitesRepository", calls[0])
            self.assertIn("-Didk.ci.publish=false", calls[0])

    def testActualElevenSelectedProducersHaveAllPrerequisitesAndFourChecksBeforeBoundedPublication(self):
        root = Path(__file__).resolve().parents[2]
        names = ["ktor-server-jwt-auth", "lib-oauth2-server-authorization-public",
                 "lib-oauth2-server-authorization-impl", "lib-oauth2-server-rest",
                 "lib-openid-oid4vp-verifier-impl", "lib-did-rest-resolver-server", "services-kms-rest",
                 "lib-oauth2-server-authorization-theme", "lib-openid-oid4vci-issuer-public",
                 "lib-openid-oid4vci-issuer-impl", "lib-data-store-blob-impl-kv"]
        stages = ci.plan(root, "private", True, self.prerequisite_environment(),
                         snapshot_prerequisites_only=True, publish_modules=",".join(names))
        self.assertEqual(["prepare"] * 6 + ["check"] * 4 + ["publish"] * 4, [s["phase"] for s in stages])
        self.assertEqual(list(ci.PACKS), [s["pack"] for s in stages[:6]])
        self.assertEqual(["infra", "identity-security", "protocols", "platform"], [s["pack"] for s in stages[6:10]])
        expected = {f":{name}:publishAllPublicationsToSphereon-opensourceRepository" for name in names}
        self.assertEqual(expected, {task for s in stages[10:] for task in s["tasks"]})
        self.assertEqual(11, sum(len(s["tasks"]) for s in stages[10:]))
        self.assertFalse(any(s.get("remote_inputs") for s in stages))

    def testSelectedExecutionRequiresCredentialsAndDefaultPlanIsUnchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.selected_fixture(directory)
            env = self.prerequisite_environment()
            default = ci.plan(root, "private", True, env, snapshot_prerequisites_only=True)
            self.assertEqual(default, ci.plan(root, "private", True, env, snapshot_prerequisites_only=True, publish_modules=""))
            stages = ci.plan(root, "private", True, env, snapshot_prerequisites_only=True, publish_modules="lib-core")
            calls = []
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "Nexus credentials"):
                    ci.execute(root, stages, "private", root / "unused", runner=lambda *a, **k: calls.append(a))
            self.assertEqual([], calls)

    def testFullPlansExplicitlyInvokeOwningRootCheck(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            for mode in ('private', 'public'):
                for publish in (False, True):
                    environment = self.prerequisite_environment() if mode == 'private' else {
                        'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': ci.PUBLIC_REPOSITORY,
                        'GITHUB_REF_NAME': 'develop',
                    }
                    with self.subTest(mode=mode, publish=publish):
                        checks = [s for s in ci.plan(root, mode, publish, environment)
                                  if s['phase'] == 'check']
                        original = 'build' if mode == 'private' else 'check'
                        self.assertEqual('.', checks[-1]['pack'])
                        self.assertEqual([original, ':check'], checks[-1]['tasks'])
                        self.assertTrue(all(s['tasks'] == [original] for s in checks[:-1]))
                        self.assertNotIn(':check', checks[-1]['exclusions'])

    def testRemoteOnlyRootCommandExecutesCheckWithoutPreparingOrPublishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            stages = ci.plan(root, 'private', False, {}, remote_only=True)
            calls = []
            ci.execute(root, stages, 'private', root / 'unused',
                       runner=lambda command, **kwargs: calls.append(command), remote_only=True)
            self.assertEqual(7, len(calls))
            self.assertEqual(['check'] * 7, [s['phase'] for s in stages])
            self.assertEqual(str(root), calls[-1][calls[-1].index('--project-dir') + 1])
            self.assertIn('build', calls[-1])
            self.assertIn(':check', calls[-1])
            self.assertTrue(all(':check' not in c for c in calls[:-1]))
            self.assertTrue(all('-Didk.ci.remote-only=true' in c and
                                '--no-build-cache' in c and '--refresh-dependencies' in c
                                for c in calls))

    def testOwningRootCheckFailureBlocksAllPublication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            stages = ci.plan(root, 'private', True, self.prerequisite_environment())
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                self.assertTrue(kwargs['check'])
                if ':check' in command:
                    raise ci.subprocess.CalledProcessError(9, command)
            with self.assertRaises(ci.subprocess.CalledProcessError) as failure:
                ci.execute(root, stages, 'private', root / 'repo', runner=runner)
            self.assertEqual(9, failure.exception.returncode)
            self.assertEqual(13, len(calls))
            self.assertIn(':check', calls[-1])
            self.assertTrue(all('-Didk.ci.publish=false' in c for c in calls))

    def testSnapshotPrerequisitePlanChecksEveryProducerBeforePublishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "platform-version.properties").write_text("platformVersion=0.26.0-SNAPSHOT")
            stages = ci.plan(root, "private", True, self.prerequisite_environment(), snapshot_prerequisites_only=True)
            self.assertEqual(["prepare"] * 6 + ["check"] * 6 + ["publish"] * 6, [s["phase"] for s in stages])
            self.assertTrue(all(s["pack"] != "." for s in stages))
            self.assertEqual(set(ci.PACKS), {s["pack"] for s in stages if s["phase"] == "check"})
            self.assertTrue(all(s["tasks"] == ["publishCiMavenRemote"] for s in stages if s["phase"] == "publish"))
            ordinary = ci.plan(root, "private", True, self.prerequisite_environment())
            self.assertEqual(["prepare"] * 6 + ["check"] * 7 + ["publish"] * 7, [s["phase"] for s in ordinary])
            remote = ci.plan(root, "private", False, {}, remote_only=True)
            self.assertEqual(["check"] * 7, [s["phase"] for s in remote])
            self.assertEqual(".", remote[-1]["pack"])

    def testSnapshotPrerequisitePlanRejectsUnsafeCombinationsAndReleaseVersions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            versions = root / "platform-version.properties"
            versions.write_text("platformVersion=0.26.0-SNAPSHOT")
            for mode, publish, remote in [("public", True, False), ("private", False, False), ("private", True, True)]:
                with self.assertRaises(ValueError):
                    ci.plan(root, mode, publish, self.prerequisite_environment(), remote, True)
            with self.assertRaises(ValueError):
                ci.plan(root, "private", True, self.prerequisite_environment() | {"GITHUB_REF": "refs/heads/main"}, snapshot_prerequisites_only=True)
            versions.write_text("platformVersion=0.26.0")
            with self.assertRaisesRegex(ValueError, "SNAPSHOT platformVersion"):
                ci.plan(root, "private", True, self.prerequisite_environment(), snapshot_prerequisites_only=True)

    def testSnapshotPrerequisiteExecutionBlocksEveryPublicationOnProducerFailure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "platform-version.properties").write_text("platformVersion=0.26.0-SNAPSHOT")
            stages = ci.plan(root, "private", True, self.prerequisite_environment(), snapshot_prerequisites_only=True)
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                self.assertTrue(kwargs["check"])
                if "build" in command and len(calls) == 7:
                    raise ci.subprocess.CalledProcessError(1, command)
            with self.assertRaises(ci.subprocess.CalledProcessError):
                ci.execute(root, stages, "private", root / "repo", runner=runner)
            self.assertEqual(12, len(calls))
            self.assertTrue(all("-Didk.ci.publish=false" in c for c in calls))

    def testOptionalCoverageExclusionDoesNotSelectAbsentTask(self):
        root = Path("checkout")
        stage = {"pack": "infra", "phase": "check", "tasks": ["build"],
                 "exclusions": ["koverVerify", ":lib-provider:jvmTest"]}
        args = ci.command(root, stage, "private", root / "maven")
        self.assertIn("-Didk.ci.exclude-kover=true", args)
        self.assertNotIn("koverVerify", args)
        self.assertEqual(["-x", ":lib-provider:jvmTest"], args[-2:])
        init = Path(__file__).with_name("pack-ci.init.gradle").read_text()
        self.assertIn("task.name == 'koverVerify'", init)
        self.assertIn("task.enabled = false", init)

    def testProductionOrderRespectsTransitiveDependencies(self):
        graph = {"wallet": {"protocols"}, "protocols": {"infra"}, "infra": {"core"}, "core": set()}
        self.assertEqual(["core", "infra", "protocols", "wallet"], ci.publication_order(graph))

    def testThreePackCycleFailsBeforeAnyCommand(self):
        with self.assertRaisesRegex(ValueError, "a -> b -> c -> a"):
            ci.publication_order({"a": {"b"}, "b": {"c"}, "c": {"a"}})

    def testTestDependencyDoesNotBecomeProductionCycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "protocols/lib/protocols/build.gradle.kts").write_text('''
                val commonMain by getting {
                    dependencies { api("com.sphereon.idk:lib-core:$version") }
                }
                val commonTest by getting {
                    dependencies { implementation("com.sphereon.idk:lib-wallet-lib:$version") }
                }
            ''')
            (root / "wallet-lib/lib/wallet-lib/build.gradle.kts").write_text(
                'api("com.sphereon.idk:lib-protocols:$version")')
            modules, _ = ci.inventory(root)
            graph = ci.pack_graph(root, modules)
            self.assertEqual({"core"}, graph["protocols"])
            self.assertEqual({"protocols"}, graph["wallet-lib"])
            stages = ci.plan(root, "private", False, {})
            self.assertEqual(["prepare"] * 6 + ["check"] * 7, [s["phase"] for s in stages])

    def testCrossPackAliasUsesPhysicalOwnerOnce(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            with (root / "identity-security/settings.gradle.kts").open("a") as file:
                file.write('includeLocal("lib-infra", "../infra/lib/infra")\n')
            modules, registered = ci.inventory(root)
            self.assertEqual("infra", modules["lib-infra"]["pack"])
            self.assertIn("lib-infra", registered["identity-security"])
            self.assertEqual(6, len(modules))

    def testConflictingOrEscapingOwnershipFails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            with (root / "core/settings.gradle.kts").open("a") as file:
                file.write('includeLocal("lib-protocols", "lib/core")\n')
            with self.assertRaisesRegex(ValueError, "Conflicting ownership"):
                ci.inventory(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            with (root / "core/settings.gradle.kts").open("a") as file:
                file.write('includeLocal("foreign", "../../../foreign")\n')
            with self.assertRaisesRegex(ValueError, "escapes"):
                ci.inventory(root)

    def testCommentsAreNotDependenciesAndUnknownEdgesFail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            build = root / "core/lib/core/build.gradle.kts"
            build.write_text('// project(":absent")\n/* api("com.sphereon.idk:missing:$version") */\n')
            modules, _ = ci.inventory(root)
            self.assertEqual((set(), set()), ci.dependencies(build, modules, {}))
            build.write_text('api("com.sphereon.idk:missing:$version")')
            with self.assertRaisesRegex(ValueError, "Unknown IDK dependencies"):
                ci.pack_graph(root, modules)

    def testProjectAndCatalogEdgesAreOrdered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "gradle").mkdir()
            (root / "gradle/libs.versions.toml").write_text(
                '[libraries]\ncore-api={module="com.sphereon.idk:lib-core",version="1"}\n')
            (root / "protocols/lib/protocols/build.gradle.kts").write_text(
                'api(projects.libInfra)\napi(libs.core.api)')
            modules, _ = ci.inventory(root)
            self.assertEqual({"core", "infra"}, ci.pack_graph(root, modules)["protocols"])

    def testManualAndPrivateRunsCannotPublishRemotely(self):
        environment = {"GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": ci.PUBLIC_REPOSITORY,
                       "GITHUB_REF_NAME": "develop"}
        self.assertTrue(ci.publication_allowed("public", environment))
        self.assertFalse(ci.publication_allowed("private", environment))
        for changed in ({"GITHUB_EVENT_NAME": "workflow_dispatch"}, {"GITHUB_EVENT_NAME": "pull_request"},
                        {"GITHUB_REF_NAME": "codex/feature"}, {"GITHUB_REPOSITORY": "example/private"}):
            self.assertFalse(ci.publication_allowed("public", environment | changed))
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            with self.assertRaisesRegex(ValueError, "restricted"):
                ci.plan(root, "private", True, environment)
            stages = ci.plan(root, "public", True, environment)
            self.assertEqual(["prepare"] * 6 + ["check"] * 7 + ["publish"] * 7,
                             [s["phase"] for s in stages])

    def testOwningPublicDispatchRequiresApprovedBranchRef(self):
        environment = {"GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_REPOSITORY": ci.PUBLIC_REPOSITORY,
                       "GITHUB_REF_NAME": "codex/infra-owned-workspaces",
                       "GITHUB_REF": "refs/heads/codex/infra-owned-workspaces"}
        self.assertTrue(ci.publication_allowed("public", environment))
        for change in ({"GITHUB_REF_NAME": "codex/other"}, {"GITHUB_REF": "refs/tags/other"},
                       {"GITHUB_REPOSITORY": "Sphereon-Opensource/Identity-Development-Kit-private"}):
            self.assertFalse(ci.publication_allowed("public", environment | change))
        self.assertFalse(ci.publication_allowed("private", environment))

    def testPrivateBootstrapPublishesOnlyMavenAfterChecks(self):
        environment = {"GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_REPOSITORY": ci.PRIVATE_REPOSITORY,
                       "GITHUB_REF_NAME": "codex/infra-owned-workspaces",
                       "GITHUB_REF": "refs/heads/codex/infra-owned-workspaces"}
        self.assertTrue(ci.publication_allowed("private", environment))
        for change in ({"GITHUB_EVENT_NAME": "push"}, {"GITHUB_REF_NAME": "develop"},
                       {"GITHUB_REF": "refs/tags/other"}, {"GITHUB_REPOSITORY": "example/private"}):
            self.assertFalse(ci.publication_allowed("private", environment | change))
        with tempfile.TemporaryDirectory() as directory:
            stages = ci.plan(self.fixture(directory), "private", True, environment)
        self.assertEqual(["prepare"] * 6 + ["check"] * 7 + ["publish"] * 7,
                         [stage['phase'] for stage in stages])
        self.assertTrue(all(stage['tasks'] == ['publishCiMavenRemote']
                            for stage in stages if stage['phase'] == 'publish'))
        self.assertNotIn('publish', [task for stage in stages for task in stage['tasks']])

    def testRemoteOnlyAcceptanceHasNoPreparationOrPublication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            stages = ci.plan(root, 'private', False, {}, remote_only=True)
            self.assertEqual(['check'] * 7, [stage['phase'] for stage in stages])
            args = ci.command(root, stages[0], 'private', root / 'unused', remote_only=True)
            self.assertIn('-Didk.ci.remote-only=true', args)
            self.assertIn('--no-build-cache', args)
            self.assertIn('--refresh-dependencies', args)
            with self.assertRaisesRegex(ValueError, 'cannot also publish'):
                ci.plan(root, 'private', True, {}, remote_only=True)

    def testExplicitBootstrapRefreshesAllToolAndArtifactDependencies(self):
        calls = []
        stages = [{'phase': phase, 'pack': 'core', 'tasks': ['fixture'], 'exclusions': []}
                  for phase in ['prepare', 'check', 'publish']]
        ci.execute(Path('checkout').resolve(), stages, 'private', Path('repo'),
                   runner=lambda command, **kwargs: calls.append(command))
        self.assertEqual(3, len(calls))
        self.assertTrue(all('--refresh-dependencies' in command for command in calls))

    def testPublicCommandsBuildOnlyTargetsTheLinuxRunnerCanProduce(self):
        stage = {"phase": "check", "pack": "core", "tasks": ["build"], "exclusions": []}
        command = ci.command(Path("checkout").resolve(), stage, "public", Path("prerequisites").resolve())
        targets = next(argument for argument in command if argument.startswith("-Dkmp.targets="))
        self.assertEqual("-Dkmp.targets=jvm,js,wasmjs,linuxx64", targets)

    def testEveryPublicationUsesThePublicTargetSet(self):
        root, repo = Path("checkout").resolve(), Path("prerequisites").resolve()
        publish = {"phase": "publish", "pack": "core", "tasks": ["publishCiMavenRemote"], "exclusions": []}
        check = {"phase": "check", "pack": "core", "tasks": ["build"], "exclusions": []}
        self.assertIn("-Dkmp.targets=jvm,js,wasmjs,linuxx64", ci.command(root, publish, "private", repo))
        self.assertIn("-Dkmp.targets=jvm", ci.command(root, check, "private", repo))

    def testExactCommandsUseOnlyCheckoutAndPrivateMaven(self):
        root, repo = Path("checkout").resolve(), Path("prerequisites").resolve()
        stage = {"phase": "check", "pack": "identity-security", "tasks": ["build"],
                 "exclusions": ci.exclusions("private", {"lib-crypto-kms-provider-aws"})}
        command = ci.command(root, stage, "private", repo)
        self.assertEqual(str(root / "identity-security"), command[command.index("--project-dir") + 1])
        self.assertIn("-Dkmp.targets=jvm", command)
        self.assertFalse(any(argument.startswith(("--max-workers", "-Dorg.gradle.workers.max",
                                                 "-Dorg.gradle.jvmargs", "-Dkotlin.daemon.jvmargs"))
                             for argument in command))
        self.assertIn("-Didk.ci.publish=false", command)
        self.assertIn("-Didk.ci.prerequisites=" + str(repo), command)
        self.assertIn(":lib-crypto-kms-provider-aws:jvmTest", command)
        self.assertNotIn(":lib-crypto-kms-provider-azure:jvmTest", command)
        self.assertNotIn("-x jvmTest", command)

    def testFailureStopsBeforeRemotePublication(self):
        calls = []

        def fail(command, **kwargs):
            calls.append(command)
            raise RuntimeError("a real check failed")

        stages = [{"phase": "check", "pack": "core", "tasks": ["check"], "exclusions": []},
                  {"phase": "publish", "pack": "core", "tasks": ["publish"], "exclusions": []}]
        with self.assertRaisesRegex(RuntimeError, "real check failed"):
            ci.execute(Path("checkout").resolve(), stages, "public", Path("repo"), runner=fail)
        self.assertEqual(1, len(calls))
        self.assertIn("-Didk.ci.publish=false", calls[0])

    def testPrivateCheckDiagnosticsStillStopBeforePublication(self):
        calls = []

        def fail(command, **kwargs):
            calls.append(command)
            self.assertTrue(kwargs['check'])
            raise ci.subprocess.CalledProcessError(1, command)

        stages = [{'phase': 'check', 'pack': 'identity-security', 'tasks': ['build'], 'exclusions': []},
                  {'phase': 'publish', 'pack': 'core', 'tasks': ['publishCiMavenRemote'], 'exclusions': []}]
        with self.assertRaises(ci.subprocess.CalledProcessError):
            ci.execute(Path('checkout').resolve(), stages, 'private', Path('repo'), runner=fail)
        self.assertEqual(1, len(calls))
        self.assertIn('--continue', calls[0])
        for mode, phase in [('public', 'check'), ('private', 'prepare'), ('private', 'publish')]:
            stage = {'phase': phase, 'pack': 'core', 'tasks': ['fixture'], 'exclusions': []}
            self.assertNotIn('--continue', ci.command(Path('checkout'), stage, mode, Path('repo')))

    def testPrivateChecksCollectFailuresAcrossPacksBeforePublication(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            self.assertTrue(kwargs['check'])
            pack = Path(command[command.index('--project-dir') + 1]).name
            if '-Didk.ci.publish=false' in command and pack in ('core', 'wallet-lib'):
                raise ci.subprocess.CalledProcessError(2, command)

        stages = [{'phase': 'check', 'pack': pack, 'tasks': ['build'], 'exclusions': []}
                  for pack in ('core', 'infra', 'wallet-lib')]
        stages.append({'phase': 'publish', 'pack': 'core', 'tasks': ['publishCiMavenRemote'], 'exclusions': []})
        with self.assertRaises(ci.subprocess.CalledProcessError) as failed:
            ci.execute(Path('checkout').resolve(), stages, 'private', Path('repo'), runner=run)
        self.assertEqual(2, failed.exception.returncode)
        self.assertEqual(3, len(calls))
        self.assertTrue(all('-Didk.ci.publish=false' in command for command in calls))

    def testPrivatePreparationFailureStopsBeforeChecksAndPublication(self):
        calls = []

        def fail(command, **kwargs):
            calls.append(command)
            raise ci.subprocess.CalledProcessError(1, command)

        stages = [{'phase': phase, 'pack': 'core', 'tasks': ['fixture'], 'exclusions': []}
                  for phase in ('prepare', 'check', 'publish')]
        with self.assertRaises(ci.subprocess.CalledProcessError):
            ci.execute(Path('checkout').resolve(), stages, 'private', Path('repo'), runner=fail)
        self.assertEqual(1, len(calls))
        self.assertNotIn('--continue', calls[0])

    def testUnrelatedWorkspaceInputsCannotRedirectCi(self):
        calls = []
        stage = {"phase": "prepare", "pack": "core", "tasks": ["publishAllPublicationsToCiPrerequisitesRepository"],
                 "exclusions": []}
        with patch.dict(os.environ, {"IDK_LOCAL_PACKS": "core", "WORKTREE_MAVEN_REPO": "other"}):
            ci.execute(Path("checkout").resolve(), [stage], "private", Path("repo"),
                       runner=lambda command, **kwargs: calls.append(kwargs))
        self.assertNotIn("IDK_LOCAL_PACKS", calls[0]["env"])
        self.assertNotIn("WORKTREE_MAVEN_REPO", calls[0]["env"])
        self.assertTrue(calls[0]["check"])

    def testOwningGradleRuntimeInputsAreInherited(self):
        calls = []
        stage = {"phase": "check", "pack": "core", "tasks": ["build"], "exclusions": []}
        runtime = {"GRADLE_OPTS": "-Dorg.gradle.workers.max=3 -Dkotlin.daemon.jvmargs=-Xmx2g",
                   "ORG_GRADLE_PROJECT_org.gradle.jvmargs": "-Xmx4g"}
        with patch.dict(os.environ, runtime):
            ci.execute(Path("checkout").resolve(), [stage], "private", Path("repo"),
                       runner=lambda command, **kwargs: calls.append((command, kwargs)))
        inherited = {name.casefold(): value for name, value in calls[0][1]["env"].items()}
        for name, value in runtime.items():
            self.assertEqual(value, inherited[name.casefold()])
        self.assertFalse(any(argument.startswith(("--max-workers", "-Dorg.gradle.workers.max",
                                                 "-Dorg.gradle.jvmargs", "-Dkotlin.daemon.jvmargs"))
                             for argument in calls[0][0]))

    def testCurrentCheckoutHasAcyclicProductionPacks(self):
        root = Path(__file__).resolve().parents[2]
        modules, _ = ci.inventory(root)
        graph = ci.pack_graph(root, modules)
        self.assertGreater(len(modules), 200)
        ordered = ci.publication_order(graph)
        for pack, prerequisites in graph.items():
            for prerequisite in prerequisites:
                self.assertLess(ordered.index(prerequisite), ordered.index(pack))
        self.assertNotIn("wallet-lib", graph["protocols"])

    def testCurrentCheckoutTestsNeverReachALaterPack(self):
        # Kotlin/JS resolves every test configuration in kotlinNpmInstall while a pack is still being prepared, so a
        # test edge to a pack that publishes later cannot resolve until that pack has been published once.
        root = Path(__file__).resolve().parents[2]
        modules, _ = ci.inventory(root)
        ordered = ci.publication_order(ci.pack_graph(root, modules))
        catalog = ci.internal_catalog(root)
        later = []
        for name, module in modules.items():
            _production, tests = ci.dependencies(module["path"] / "build.gradle.kts", modules, catalog)
            for dependency in tests:
                if ordered.index(modules[dependency]["pack"]) > ordered.index(module["pack"]):
                    later.append(f"{name} -> {dependency}")
        self.assertEqual([], sorted(later))


if __name__ == "__main__":
    unittest.main()
