from lazy import lazy
from mr.awsome.common import BaseMaster, StartupScriptMixin
from mr.awsome.config import BaseMassager, BooleanMassager
from mr.awsome.config import IntegerMassager
from mr.awsome.config import StartupScriptMassager, UserMassager
from mr.awsome.config import value_asbool
from mr.awsome.plain import Instance as PlainInstance
import logging
import sys
import time


log = logging.getLogger('mr.awsome.openvz')


class OpenVZError(Exception):
    pass


class Instance(PlainInstance, StartupScriptMixin):
    sectiongroupname = 'vz-instance'

    def get_host(self):
        return self.config.get('host', self.config['ip'])

    def get_fingerprint(self):
        out, err = self.master.vzctl('exec', self.config['veid'], cmd='ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub')
        info = out.split()
        return info[1]

    def vzlist(self, **kwargs):
        try:
            return self.master.vzlist(**kwargs)
        except ValueError:
            log.exception("Error in vzlist")
            sys.exit(1)

    def status(self):
        try:
            veid = self.config['veid']
        except:
            log.error("No veid set in vz-instance:%s.", self.id)
            sys.exit(1)
        status = self.vzlist(veid=veid)
        if status is None:
            log.info("Instance '%s' (%s) unavailable", self.id, veid)
            return
        if status['status'] != 'running':
            log.info("Instance state: %s", status['status'])
            return
        log.info("Instance running.")
        log.info("Instances host name %s", status['hostname'])
        log.info("Instances ip address %s", status['ip'])

    def log_cmd_output(self, out, err):
        if out:
            for line in out.split('\n'):
                log.info(line)
        if err:
            for line in err.split('\n'):
                log.info(line)

    def start(self, overrides=None):
        veid = self.config['veid']
        status = self.vzlist(veid=veid)
        create = False
        if status is None:
            create = True
            startup_script = self.startup_script(overrides=overrides)
            log.info("Creating instance '%s'", veid)
            try:
                self.master.vzctl(
                    'create',
                    veid,
                    ip=self.config['ip'],
                    hostname=self.config['hostname'],
                    ostemplate=self.config['ostemplate'])
            except OpenVZError as e:
                for line in e.args[0].split('\n'):
                    log.error(line)
                sys.exit(1)
            status = self.vzlist(veid=veid)
        options = {}
        for key in self.config:
            if key.startswith('set-'):
                options[key] = self.config[key]
        if options:
            log.info("Setting options")
            self.master.vzctl('set', veid, save=True, **options)
        if status['status'] != 'stopped':
            log.info("Instance state: %s", status['status'])
            log.info("Instance already started")
            return True
        mounts = self.config.get('mounts', [])
        if mounts:
            log.info("Setting up mounts for instance '%s'", veid)
            mount_script = [
                '#!/bin/bash',
                'source /etc/vz/vz.conf',
                'source ${VE_CONFFILE}']
            for mount in mounts:
                opts = dict(
                    src=mount['src'].format(veid=veid).replace('"', '\\"'),
                    dst=mount['dst'].format(veid=veid).replace('"', '\\"'))
                if mount.get('create', False):
                    mount_script.append(
                        'test ! -e "{src}" && mkdir "{src}"'.format(**opts))
                mount_script.append(
                    'test ! -e ${{VE_ROOT}}"{dst}" && mkdir ${{VE_ROOT}}"{dst}"'.format(**opts))
                mount_script.append(
                    'mount -n -t simfs "{src}" ${{VE_ROOT}}"{dst}" -o "{src}"'.format(**opts))
            mount_script.append('')
            mount_script = '\n'.join(mount_script)
            mount_script_filename = '/etc/vz/conf/%s.mount' % veid
            cmd_fmt = 'bash -c "echo -e \\"{script}\\" | base64 -d > {filename}"'
            cmd = cmd_fmt.format(
                filename=mount_script_filename,
                script=mount_script.encode('base64').replace('\n', '\\n'))
            out, err = self.master._exec(
                self.master.binary_prefix + cmd,
                debug=self.master.debug)
            self.log_cmd_output(out, err)
            out, err = self.master._exec(
                self.master.binary_prefix + 'chmod 0700 %s' % mount_script_filename,
                debug=self.master.debug)
            self.log_cmd_output(out, err)
        log.info("Starting instance '%s'", veid)
        self.master.vzctl('start', veid)
        if create and startup_script:
            log.info("Instance started, waiting until it's available")
            for i in range(60):
                sys.stdout.write(".")
                sys.stdout.flush()
                out, err = self.master.vzctl('exec', veid, cmd="runlevel")
                if not out.startswith("unknown"):
                    break
                time.sleep(5)
            else:
                log.error("Timeout while waiting for instance to start after creation!")
                sys.exit(1)
            sys.stdout.write("\n")
            sys.stdout.flush()
            log.info("Running startup_script")
            cmd_fmt = 'base64 -d > /etc/startup_script <<_END_OF_SCRIPT_\n%s\n_END_OF_SCRIPT_\n'
            cmd = cmd_fmt % startup_script.encode('base64')
            out, err = self.master.vzctl(
                'exec',
                veid,
                cmd=cmd)
            if out:
                for line in out.split('\n'):
                    log.info(line)
            if err:
                for line in err.split('\n'):
                    log.info(line)
            out, err = self.master.vzctl(
                'exec',
                veid,
                cmd='chmod 0700 /etc/startup_script')
            if out:
                for line in out.split('\n'):
                    log.info(line)
            if err:
                for line in err.split('\n'):
                    log.info(line)
            out, err = self.master.vzctl(
                'exec',
                veid,
                cmd='/etc/startup_script &')
            if out:
                for line in out.split('\n'):
                    log.info(line)
            if err:
                for line in err.split('\n'):
                    log.info(line)
        else:
            log.info("Instance started")
        return True

    def stop(self):
        veid = self.config['veid']
        status = self.vzlist(veid=veid)
        if status is None:
            log.info("Instance '%s' (%s) unavailable", self.id, veid)
            return
        if status['status'] != 'running':
            log.info("Instance state: %s", status['status'])
            log.info("Instance not stopped")
            return
        log.info("Stopping instance '%s'", veid)
        self.master.vzctl('stop', veid)
        log.info("Instance stopped")

    def terminate(self):
        veid = self.config['veid']
        if self.config.get('no-terminate', False):
            log.error("Instance '%s' (%s) is configured not to be terminated.", self.id, veid)
            return
        status = self.vzlist(veid=veid)
        if status is None:
            log.info("Instance '%s' (%s) unavailable", self.id, veid)
            return
        if status['status'] == 'running':
            log.info("Stopping instance '%s'", veid)
            self.master.vzctl('stop', veid)
            log.info("Instance stopped")
        status = self.vzlist(veid=veid)
        if status is None:
            log.error("Unknown instance status")
            log.info("Instance not stopped")
        if status['status'] != 'stopped':
            log.info("Instance state: %s", status['status'])
            log.info("Instance not stopped")
            return
        log.info("Terminating instance '%s' (%s)", self.id, veid)
        self.master.vzctl('destroy', veid)
        log.info("Instance terminated")


class Master(BaseMaster):
    sectiongroupname = 'vz-instance'
    instance_class = Instance

    def __init__(self, *args, **kwargs):
        BaseMaster.__init__(self, *args, **kwargs)
        self.instance = PlainInstance(self, self.id, self.master_config)
        self.instance.sectiongroupname = 'vz-master'
        self.instances[self.id] = self.instance
        self.debug = self.master_config.get('debug-commands', False)

    @lazy
    def binary_prefix(self):
        if self.master_config.get('sudo'):
            return "sudo "
        return ""

    @lazy
    def vzctl_binary(self):
        binary = self.binary_prefix + self.master_config.get('vzctl', 'vzctl')
        return binary

    @lazy
    def vzlist_binary(self):
        binary = self.binary_prefix + self.master_config.get('vzlist', 'vzlist')
        return binary

    @property
    def conn(self):
        return self.instance.conn

    def _exec(self, cmd, debug=False):
        if debug:
            log.info(cmd)
        rin, rout, rerr = self.conn.exec_command(cmd)
        out = rout.read()
        err = rerr.read()
        if debug and out.strip():
            for line in out.split('\n'):
                log.info(line)
        if debug and err.strip():
            for line in err.split('\n'):
                log.error(line)
        return out, err

    def _vzctl(self, cmd):
        return self._exec("%s %s" % (self.vzctl_binary, cmd), self.debug)

    def _vzlist(self, cmd):
        return self._exec("%s %s" % (self.vzlist_binary, cmd), self.debug)

    def vzctl(self, command, veid, **kwargs):
        if command == 'status':
            out, err = self._vzctl('status %s' % veid)
            out = out.strip().split()
            if out[0] != 'VEID':
                raise ValueError
            if out[0] != 'VEID':
                raise ValueError
            if int(out[1]) != int(veid):
                raise ValueError
            return {
                'exists': out[2],
                'filesystem': out[3],
                'status': out[4]}
        elif command == 'start':
            out, err = self._vzctl('start %s' % veid)
            if err:
                raise OpenVZError(err.strip())
        elif command == 'stop':
            out, err = self._vzctl('stop %s' % veid)
            if err:
                raise OpenVZError(err.strip())
        elif command == 'destroy':
            out, err = self._vzctl('destroy %s' % veid)
            if err:
                raise OpenVZError(err.strip())
        elif command == 'set':
            options = []
            if 'save' in kwargs and kwargs['save']:
                options.append('--save')
            for key in kwargs:
                if not key.startswith('set-'):
                    continue
                options.append("--%s %s" % (key[4:], kwargs[key]))
            options = " ".join(options)
            self._vzctl('set %s %s' % (veid, options))
        elif command == 'exec':
            return self._vzctl('exec %s "%s"' % (veid, kwargs['cmd']))
        elif command == 'create':
            cmd = 'create %s --ostemplate "%s" --ipadd "%s" --hostname "%s"' % (
                veid,
                kwargs['ostemplate'],
                kwargs['ip'],
                kwargs['hostname'])
            out, err = self._vzctl(cmd)
            if err:
                raise OpenVZError(err.strip())
        else:
            raise ValueError("Unknown command '%s'" % command)

    @lazy
    def vzlist_options(self):
        out, err = self._exec("%s -L" % self.vzlist_binary, self.debug)
        err = err.strip()
        if 'vzlist: command not found' in err:
            for line in err.split('\n'):
                log.error(line)
            sys.exit(1)
        header_map = {}
        option_map = {}
        for line in out.split('\n'):
            line = line.strip()
            if not line:
                continue
            option, header = line.split()
            option_map[option] = header
            if header in header_map:
                continue
            header_map[header] = option
        return header_map, option_map

    def vzlist(self, veid=None, info=None):
        header_map, option_map = self.vzlist_options
        veid_option = header_map[option_map['veid']]
        if info is None:
            info = (veid_option, 'status', 'ip', 'hostname', 'name')
        info = set(info)
        info.add(veid_option)
        unknown = info - set(option_map)
        if unknown:
            raise ValueError("Unknown options in vzlist call: %s" % ", ".join(unknown))
        if veid is None:
            cmd = '-a -o %s' % ','.join(sorted(info))
            out, err = self._vzlist(cmd)
            err = err.strip()
        else:
            cmd = '-a -o %s %s' % (','.join(sorted(info)), veid)
            out, err = self._vzlist(cmd)
            err = err.strip()
        if err in ('Container(s) not found', 'VE not found'):
            if veid is None:
                return {}
            else:
                return None
        elif err:
            raise ValueError(err)
        lines = out.split('\n')
        headers = [header_map[x] for x in lines[0].split()]
        results = {}
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            values = dict(zip(headers, line.split()))
            results[values[veid_option]] = values
            del values[veid_option]
        if veid is not None:
            return results.get(str(veid))
        return results


class MountsMassager(BaseMassager):
    def __call__(self, config, sectionname):
        value = BaseMassager.__call__(self, config, sectionname)
        mounts = []
        for line in value.split('\n'):
            mount_options = line.split()
            if not len(mount_options):
                continue
            options = {}
            for mount_option in mount_options:
                if '=' not in mount_option:
                    raise ValueError("Mount option '%s' contains no equal sign." % mount_option)
                (key, value) = mount_option.split('=')
                (key, value) = (key.strip(), value.strip())
                if key == 'create':
                    value = value_asbool(value)
                    if value is None:
                        raise ValueError("Unknown value %s for option %s in %s of %s:%s." % (value, key, self.key, self.sectiongroupname, sectionname))
                options[key] = value
            mounts.append(options)
        return tuple(mounts)


def get_massagers():
    massagers = []

    sectiongroupname = 'vz-instance'
    massagers.extend([
        IntegerMassager(sectiongroupname, 'veid'),
        UserMassager(sectiongroupname, 'user'),
        BooleanMassager(sectiongroupname, 'no-terminate'),
        MountsMassager(sectiongroupname, 'mounts'),
        StartupScriptMassager(sectiongroupname, 'startup_script')])

    sectiongroupname = 'vz-master'
    massagers.extend([
        UserMassager(sectiongroupname, 'user'),
        BooleanMassager(sectiongroupname, 'sudo'),
        BooleanMassager(sectiongroupname, 'debug-commands')])

    return massagers


def get_masters(aws):
    masters = aws.config.get('vz-master', {})
    for master, master_config in masters.iteritems():
        yield Master(aws, master, master_config)


plugin = dict(
    get_massagers=get_massagers,
    get_masters=get_masters)
