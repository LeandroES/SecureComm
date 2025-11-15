import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import App from './App';

describe('App', () => {
    it('renders placeholder headings', () => {
        render(<App />);
        expect(screen.getByText(/SecureComm/i)).toBeTruthy();
        expect(screen.getByText(/Login \/ Registro/i)).toBeTruthy();
    });
});