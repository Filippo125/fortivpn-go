package main

import (
	"errors"
	"fmt"
	"io"

	appconfig "github.com/Filippo125/fortivpn-go/internal/config"
)

const zshCompletion = `#compdef fortivpn

_fortivpn_instance_selectors() {
  local config="" index executable="${words[1]}"
  for (( index = 2; index <= CURRENT; index++ )); do
    case "${words[index]}" in
      --config)
        (( index++ ))
        config="${words[index]}"
        ;;
      --config=*) config="${words[index]#--config=}" ;;
    esac
  done
	if [[ -z "$config" ]]; then
		config="${FORTIVPN_CONFIG:-$HOME/.config/fortivpn/config.yaml}"
	fi
  local -a selectors
  selectors=("${(@f)$(command "$executable" __complete-instances --config "$config" 2>/dev/null)}")
  compadd -- "${selectors[@]}"
}

_fortivpn() {
	if [[ "${words[2]}" == "connect" && CURRENT -eq 3 ]]; then
		_fortivpn_instance_selectors
		return
	fi
  if [[ "${words[CURRENT-1]}" == "--instance" ]]; then
    _fortivpn_instance_selectors
    return
  fi
  if [[ "$PREFIX" == --instance=* ]]; then
    compset -P '*='
    _fortivpn_instance_selectors
    return
  fi
  _arguments \
    '--config[JSON or YAML configuration file]:file:_files' \
    '--instance[instance selector]:selector:_fortivpn_instance_selectors' \
    '*:argument:'
}

compdef _fortivpn fortivpn
`

const bashCompletion = `_fortivpn() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local prev=""
  local config=""
  local i word
  (( COMP_CWORD > 0 )) && prev="${COMP_WORDS[COMP_CWORD-1]}"
  for (( i = 1; i < COMP_CWORD; i++ )); do
    word="${COMP_WORDS[i]}"
    if [[ "$word" == "--config" ]] && (( i + 1 < COMP_CWORD )); then
      (( i++ ))
      config="${COMP_WORDS[i]}"
    elif [[ "$word" == --config=* ]]; then
      config="${word#--config=}"
    fi
  done
	[[ -z "$config" ]] && config="${FORTIVPN_CONFIG:-$HOME/.config/fortivpn/config.yaml}"
	if [[ "$COMP_CWORD" -eq 2 && "${COMP_WORDS[1]}" == "connect" ]]; then
		local selector
		COMPREPLY=()
		while IFS= read -r selector; do
			[[ "$selector" == "$cur"* ]] && COMPREPLY+=("$selector")
		done < <("${COMP_WORDS[0]}" __complete-instances --config "$config" 2>/dev/null)
		return
	fi
  if [[ "$prev" == "--instance" && -n "$config" ]]; then
    local selector
    COMPREPLY=()
    while IFS= read -r selector; do
      [[ "$selector" == "$cur"* ]] && COMPREPLY+=("$selector")
    done < <("${COMP_WORDS[0]}" __complete-instances --config "$config" 2>/dev/null)
    return
  fi
  if [[ "$prev" == "--config" ]]; then
    COMPREPLY=( $(compgen -f -- "$cur") )
    return
  fi
  COMPREPLY=( $(compgen -W '--config --instance --protocol --port --realm --remote-id --transport --tcp-port --socket --ip-mode --browser --saml --username --password --password-stdin --psk --timeout --insecure --debug' -- "$cur") )
}

complete -F _fortivpn fortivpn
`

const fishCompletion = `function __fortivpn_instance_selectors
    set -l tokens (commandline -opc)
    set -l config
    for i in (seq 1 (count $tokens))
        if test "$tokens[$i]" = --config
            set -l next (math $i + 1)
            if test $next -le (count $tokens)
                set config "$tokens[$next]"
            end
        else if string match -q -- '--config=*' "$tokens[$i]"
            set config (string replace -- '--config=' '' "$tokens[$i]")
        end
    end
	if test -z "$config"
		set config "$FORTIVPN_CONFIG"
	end
	if test -z "$config"
		set config "$HOME/.config/fortivpn/config.yaml"
	end
	command fortivpn __complete-instances --config "$config" 2>/dev/null
end

complete -c fortivpn -l config -r -F -d 'JSON or YAML configuration file'
complete -c fortivpn -l instance -r -a '(__fortivpn_instance_selectors)' -d 'Instance selector'
complete -c fortivpn -n '__fish_seen_subcommand_from connect' -a '(__fortivpn_instance_selectors)' -d 'Instance selector'
`

func runCompletion(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: fortivpn completion <bash|zsh|fish>")
	}
	var script string
	switch args[0] {
	case "zsh":
		script = zshCompletion
	case "bash":
		script = bashCompletion
	case "fish":
		script = fishCompletion
	default:
		return fmt.Errorf("unsupported shell %q: use bash, zsh, or fish", args[0])
	}
	_, err := io.WriteString(out, script)
	return err
}

func completeInstances(args []string, out io.Writer) error {
	path, err := configPath(args)
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("--config is required")
	}
	selectors, err := appconfig.InstanceSelectors(path)
	if err != nil {
		return err
	}
	for _, selector := range selectors {
		fmt.Fprintln(out, selector)
	}
	return nil
}
