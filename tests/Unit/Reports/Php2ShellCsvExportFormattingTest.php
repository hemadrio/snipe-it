<?php

namespace Tests\Unit\Reports;

use League\Csv\EscapeFormula;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class Php2ShellCsvExportFormattingTest extends TestCase
{
    private EscapeFormula $formatter;

    protected function setUp(): void
    {
        parent::setUp();
        $this->formatter = new EscapeFormula('`');
    }

    #[DataProvider('formulaTriggerProvider')]
    public function test_formula_triggering_values_are_escaped(string $input): void
    {
        $escaped = $this->formatter->escapeRecord([$input]);
        $this->assertNotEquals($input, $escaped[0], "Value '{$input}' should be escaped by EscapeFormula.");
        $this->assertStringStartsWith('`', $escaped[0], 'Escaped value should start with backtick prefix.');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function formulaTriggerProvider(): array
    {
        return [
            'equals sign' => ['=CMD("malicious")'],
            'plus sign' => ['+HYPERLINK("evil")'],
            'minus sign' => ['-@SUM(A1)'],
            'at sign' => ['@SUM(A1:A10)'],
        ];
    }

    public function test_normal_values_are_not_escaped(): void
    {
        $normal = ['Dockerfile', '8.3.36', 'patched', 'infrastructure'];
        $escaped = $this->formatter->escapeRecord($normal);

        foreach ($normal as $i => $value) {
            $this->assertSame($value, $escaped[$i], "Normal value '{$value}' should not be modified.");
        }
    }
}
