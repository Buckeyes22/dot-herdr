"""The setup terminal must not turn input typed during a wait into consent."""
import os
import pty
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from dot_herdr import onboarding


class SetupTerminalTests(unittest.IsolatedAsyncioTestCase):
    def test_tty_prompt_discards_input_typed_before_prompt(self):
        master,slave=pty.openpty()
        reader=os.fdopen(os.dup(slave))
        writer=threading.Thread(target=lambda:(time.sleep(.1),os.write(master,b'y\n')))
        try:
            os.write(master,b'plugin_asdk_app_pasted\n\x1b[A\n')
            writer.start()
            with patch.object(sys,'stdin',reader):
                answer=onboarding.ask_clean(lambda _:reader.readline(),'Approve? ')
            self.assertEqual(answer.strip(),'y')
        finally:
            writer.join(timeout=1);reader.close();os.close(slave);os.close(master)

    async def test_invalid_confirmation_reasks_without_closing_window(self):
        answers=iter(['plugin_asdk_app_pasted\x1b[A','y'])
        hints=[]
        selected=await onboarding.confirm_candidate([{'subject':'alice','principal':'profile-id'}],
            'https://mcp.example.test',lambda prompt:next(answers),hints.append)
        self.assertEqual(selected,'profile-id')
        self.assertEqual(len([line for line in hints if 'Try again' in line]),1)

    async def test_bounded_pairing_reader_discards_waiting_garbage_then_approves(self):
        master,slave=pty.openpty();reader=os.fdopen(os.dup(slave));lines=[]
        writer=threading.Thread(target=lambda:(time.sleep(.2),os.write(master,b'y\n')))
        try:
            os.write(master,b'plugin_asdk_app_pasted\n\x1b[A\n')
            writer.start()
            with patch.object(sys,'stdin',reader):
                selected=await onboarding.confirm_candidate(
                    [{'subject':'alice','principal':'81e0359a4569f267fff045b6597afe76b1661721677599de2ffa470639099e01'}],
                    'https://mcp.example.test',
                    lambda prompt:onboarding.answer_before_deadline(prompt,input,lines.append,time.monotonic()+2,time.monotonic),lines.append)
            self.assertEqual(selected,'81e0359a4569f267fff045b6597afe76b1661721677599de2ffa470639099e01')
            self.assertFalse(any('Try again' in line for line in lines))
        finally:
            writer.join(timeout=1);reader.close();os.close(slave);os.close(master)

    def test_cli_quiet_default_and_debug_override(self):
        code="import dot_herdr.cli,logging,warnings; warnings.warn(\"TypedDict class 'RequestParamsMeta' allows extra items, but 'extra' configuration is set to `'forbid'`.\"); print(logging.getLogger('mcp.server').getEffectiveLevel(),logging.getLogger('httpx').getEffectiveLevel())"
        for debug,expected in ((False,'30 30'),(True,'20 20')):
            environment=os.environ.copy()
            if debug:environment['DOT_HERDR_DEBUG']='1'
            else:environment.pop('DOT_HERDR_DEBUG',None)
            result=subprocess.run([sys.executable,'-c',code],env=environment,text=True,capture_output=True,check=True)
            self.assertEqual(result.stdout.strip(),expected)
            self.assertEqual(bool(result.stderr),debug)
