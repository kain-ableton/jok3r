#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

def enable(max_concurrent: int = 8):
    from lib.core.ServiceChecks import ServiceChecks
    from lib.execution_v2 import run_plan
    from lib.output.Output import Output
    from lib.output.Logger import logger

    def _modern_run(self, target, arguments, sqlsession,
                    filter_categories=None, filter_checks=None,
                    attack_profile=None, attack_progress=None):
        from apikeys import API_KEYS
        from lib.requester.Filter import Filter, FilterOperator
        from lib.requester.Condition import Condition
        from lib.requester.ResultsRequester import ResultsRequester
        from lib.utils.StringUtils import StringUtils
        from lib.db.CommandOutput import CommandOutput
        from lib.smartmodules.SmartPostcheck import SmartPostcheck
        from lib.core.Constants import FilterData

        if filter_categories is None:
            filter_categories = self.categories

        def _append_check_commands(plan, check, category, target, arguments):
            for command in check.commands:
                if not command.context_requirements.check_target_compliance(target):
                    continue
                cmdline = command.get_cmdline(check.tool, target, arguments)
                if not cmdline:
                    continue
                argv = ['/bin/bash', '-lc', cmdline]
                plan.append({
                    'tool': check.tool.name,
                    'argv': argv,
                    'stage': category,
                    'timeout': 1200,
                    'meta': {
                        'service_id': target.service.id,
                        'check_name': check.name,
                        'category': category,
                        'cmdline': cmdline,
                        'target': target.get_service_name(),
                    },
                })

        def _build_plan_standard(target, arguments, sqlsession, filter_categories):
            plan = []
            nb_checks = self.nb_checks()
            j = 1
            for category in self.categories:
                if category not in filter_categories:
                    continue
                Output.title1('Category > {cat}'.format(cat=category.capitalize()))
                i = 1
                for check in self.checks[category]:
                    if i > 1:
                        print()
                    results_req = ResultsRequester(sqlsession)
                    results_req.select_mission(target.service.host.mission.name)
                    flt = Filter(FilterOperator.AND)
                    flt.add_condition(Condition(target.service.id, FilterData.SERVICE_ID))
                    flt.add_condition(Condition(check.name, FilterData.CHECK_NAME))
                    results_req.add_filter(flt)
                    result = results_req.get_first_result()
                    if result is None or arguments.args.recheck is True:
                        if check.required_apikey and not API_KEYS.get(check.required_apikey):
                            logger.warning('Check {0} requires missing API key "{1}", skipped'.format(check.name, check.required_apikey))
                        elif check.check_target_compliance(target):
                            Output.title2('[{cat}][Check {num:02}/{tot:02}] {name} > {desc}'.format(
                                cat=category.capitalize(), num=j, tot=nb_checks, name=check.name, desc=check.description))
                            if not check.tool.installed:
                                logger.warning('Skipped: the tool "{0}" is not installed'.format(check.tool.name))
                            else:
                                _append_check_commands(plan, check, category, target, arguments)
                        else:
                            logger.info('[{cat}][Check {num:02}/{tot:02}] {name} > Skipped due to context requirements'.format(
                                cat=category.capitalize(), num=j, tot=nb_checks, name=check.name))
                    else:
                        logger.info('[{cat}][Check {num:02}/{tot:02}] {name} > Skipped (already run)'.format(
                            cat=category.capitalize(), num=j, tot=nb_checks, name=check.name))
                    i += 1
                    j += 1
            return plan

        def _build_plan_special(target, arguments, sqlsession, filter_checks=None, attack_profile=None):
            plan = []
            if filter_checks:
                filter_checks = [x for x in filter_checks if self.is_existing_check(x)]
                if not filter_checks:
                    logger.warning('None of the selected checks exist for service {0}'.format(target.get_service_name()))
                    return []
                logger.info('Selected check(s) that will be run:')
                for c in filter_checks:
                    chk = self.get_check(c)
                    if chk:
                        Output.print(' | - {name} ({category})'.format(name=c, category=chk.category))
            else:
                if not attack_profile.is_service_supported(target.get_service_name()):
                    logger.warning('Profile {0} not supported for {1}'.format(attack_profile, target.get_service_name()))
                    return []
                filter_checks = attack_profile.get_checks_for_service(target.get_service_name())
                logger.info('Selected attack profile: {0}'.format(attack_profile))

            i = 1
            for checkname in filter_checks:
                print()
                check = self.get_check(checkname)
                if check is None:
                    continue
                results_req = ResultsRequester(sqlsession)
                results_req.select_mission(target.service.host.mission.name)
                flt = Filter(FilterOperator.AND)
                flt.add_condition(Condition(target.service.id, FilterData.SERVICE_ID))
                flt.add_condition(Condition(check.name, FilterData.CHECK_NAME))
                results_req.add_filter(flt)
                result = results_req.get_first_result()
                if result is None or arguments.args.recheck is True:
                    if check.required_apikey and not API_KEYS.get(check.required_apikey):
                        logger.warning('Check {0} requires missing API key "{1}", skipped'.format(check.name, check.required_apikey))
                    elif check.check_target_compliance(target):
                        Output.title2('[Check {num:02}/{tot:02}] {name} > {desc}'.format(
                            num=i, tot=len(filter_checks), name=check.name, desc=check.description))
                        if not check.tool.installed:
                            logger.warning('Skipped: the tool "{0}" is not installed'.format(check.tool.name))
                        else:
                            _append_check_commands(plan, check, check.category, target, arguments)
                    else:
                        logger.info('[Check {num:02}/{tot:02}] {name} > Skipped due to context requirements'.format(
                            num=i, tot=len(filter_checks), name=check.name))
                else:
                    logger.info('[Check {num:02}/{tot:02}] {name} > Skipped (already run)'.format(
                        num=i, tot=len(filter_checks), name=check.name))
                i += 1
            return plan

        if filter_checks is None and attack_profile is None:
            plan = _build_plan_standard(target, arguments, sqlsession, filter_categories)
        else:
            plan = _build_plan_special(target, arguments, sqlsession, filter_checks, attack_profile)

        if not plan:
            logger.info('Modern runner: nothing to execute for this service')
            return

        results = run_plan(plan, max_concurrent=max_concurrent)

        from lib.requester.ResultsRequester import ResultsRequester
        from lib.requester.Filter import Filter, FilterOperator
        from lib.requester.Condition import Condition

        def _group_results_by_check(target, results):
            grouped = {}
            service_id = target.service.id
            for r in results:
                meta = r.meta or {}
                check_name = meta.get('check_name')
                category = meta.get('category')
                cmdline = meta.get('cmdline')
                if not check_name or not category or not cmdline:
                    continue
                key = (service_id, check_name, category)
                grouped.setdefault(key, []).append((cmdline, r))
            return grouped

        groups = _group_results_by_check(target, results)
        if not groups:
            return

        for (service_id, check_name, category), entries in groups.items():
            command_outputs = []
            for cmdline, r in entries:
                stdout = StringUtils.interpret_ansi_escape_clear_lines(r.stdout)
                outputraw = StringUtils.remove_ansi_escape(stdout)
                co = CommandOutput(cmdline=cmdline, output=stdout, outputraw=outputraw)
                command_outputs.append(co)
                postcheck = SmartPostcheck(target.service, r.name, "{0}\n{1}".format(cmdline, outputraw))
                postcheck.run()

            results_req = ResultsRequester(sqlsession)
            results_req.add_result(service_id, check_name, category, command_outputs)
        sqlsession.commit()

    ServiceChecks.run = _modern_run
