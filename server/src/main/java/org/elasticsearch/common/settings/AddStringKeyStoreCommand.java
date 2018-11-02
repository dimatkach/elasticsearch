/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.common.settings;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.elasticsearch.cli.EnvironmentAwareCommand;
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.env.Environment;

/**
 * A subcommand for the keystore cli which adds a string setting.
 */
class AddStringKeyStoreCommand extends EnvironmentAwareCommand {

    private final OptionSpec<Void> stdinOption;
    private final OptionSpec<Void> cmdlineOption;
    private final OptionSpec<Void> forceOption;
    private final OptionSpec<String> arguments;

    private final boolean defaultAsFile;

    AddStringKeyStoreCommand(boolean defaultAsFile) {
        super("Add a string setting to the keystore");
        this.stdinOption = parser.acceptsAll(Arrays.asList("x", "stdin"), "Read setting value from stdin");
        this.cmdlineOption = parser.acceptsAll(Arrays.asList("c", "cmdline"), "Command line parameters are in `key=value` format");
        this.forceOption = parser.acceptsAll(Arrays.asList("f", "force"), "Overwrite existing setting without prompting");
        this.arguments = parser.nonOptions("setting name");
        this.defaultAsFile = defaultAsFile;
    }

    AddStringKeyStoreCommand() { this(false); }

    // pkg private so tests can manipulate
    InputStream getStdin() {
        return System.in;
    }

    @Override
    protected void execute(Terminal terminal, OptionSet options, Environment env) throws Exception {
        KeyStoreWrapper keystore = KeyStoreWrapper.load(env.configFile());

        if (keystore == null) {
            if (options.has(forceOption) == false &&
                terminal.promptYesNo("The elasticsearch keystore does not exist. Do you want to create it?", false) == false) {
                terminal.println("Exiting without creating keystore.");
                return;
            }
            keystore = KeyStoreWrapper.create();
            keystore.save(env.configFile(), new char[0] /* always use empty passphrase for auto created keystore */);
            terminal.println("Created elasticsearch keystore in " + env.configFile());
        } else {
            keystore.decrypt(new char[0] /* TODO: prompt for password when they are supported */);
        }

        List<String> settings = arguments.values(options);
        if (settings == null) {
            throw new UserException(ExitCodes.USAGE, "The setting name can not be null");
        }

        boolean asFile = defaultAsFile;
        for(Iterator<String> it = settings.iterator(); it.hasNext(); ) {
            String setting = it.next();
            if (keystore.getSettingNames().contains(setting) && options.has(forceOption) == false) {
                if (terminal.promptYesNo("Setting " + setting + " already exists. Overwrite?", false) == false) {
                    terminal.println("Exiting without modifying keystore.");
                    return;
                }
            }

            if(setting.equals("string")) {
                asFile = false;
                continue;
            } else if(setting.equals("file")) {
                asFile = true;
                continue;
            }

            if((asFile || options.has(cmdlineOption)) && !it.hasNext()) {
                throw new UserException(
                    ExitCodes.USAGE,
                    "Missing " + (asFile ? "filename" : "secret value") + " on command line."
                );
            } else if(asFile) {
                addFile(keystore, setting, it.next());
            } else if(options.has(cmdlineOption)) {
                addString(keystore, setting, it.next().toCharArray());
            } else {
                addString(keystore, setting, readValue(setting, terminal, options.has(stdinOption)));
            }
        }

        keystore.save(env.configFile(), new char[0]);
    }

    @SuppressForbidden(reason="file arg for cli")
    private Path getPath(String file) {
        return PathUtils.get(file);
    }

    private char[] readValue(String key, Terminal terminal, boolean fromStdin) throws IOException {
        if(fromStdin) {
            return new BufferedReader(new InputStreamReader(getStdin(), StandardCharsets.UTF_8))
                .readLine()
                .toCharArray();
        } else {
            return terminal.readSecret("Enter valkue for " + key + ": ");
        }
    }

    private void addString(
        KeyStoreWrapper keystore,
        String key,
        char[] value
    ) throws UserException {
        try {
            keystore.setString(key, value);
        } catch (IllegalArgumentException e) {
            throw new UserException(ExitCodes.DATA_ERROR, "String value must contain only ASCII");
        }
    }

    private void addFile(KeyStoreWrapper keystore, String key, String filename) throws UserException, IOException {
        Path file = getPath(filename);
        if (Files.exists(file) == false) {
            throw new UserException(ExitCodes.IO_ERROR, "File [" + file.toString() + "] does not exist");
        }

        keystore.setFile(key, Files.readAllBytes(file));
    }
}
