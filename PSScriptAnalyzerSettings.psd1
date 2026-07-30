@{
    Severity = @('Error', 'Warning')

    IncludeRules = @(
        'PSUseCompatibleSyntax',
        'PSAvoidUsingInvokeExpression',
        'PSMisleadingBacktick',
        'PSPossibleIncorrectUsageOfAssignmentOperator',
        'PSPossibleIncorrectUsageOfRedirectionOperator'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
